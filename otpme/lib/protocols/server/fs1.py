# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import grp
import zlib
import time
import errno
import setproctitle

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import jwt
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import filetools
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
        self.share_uuid = None
        # Will hold share root.
        self.root = None
        # Share mounted.
        self.mounted = False
        # Share is home share.
        self.home_share = False
        # Home share encryption data.
        self.home_share_enc_data = None
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
        # Deny access set by handle_share_setttings().
        self.block_access = False
        # Indicates shutdown of connection.
        self.shutdown = False
        # Share settings handler thread.
        self.share_handler_thread = None
        # Call parent class init.
        OTPmeFsServer1.__init__(self, **kwargs)

    def _pre_init(self, *args, **kwargs):
        """ Init protocol handler. """
        # Our PID.
        self.pid = os.getpid()
        # Do atfork stuff.
        multiprocessing.atfork(quiet=True)
        self.share_handler_thread = multiprocessing.start_thread(name=self.name,
                                                target=self.handle_share_setttings)

    def set_proctitle(self, username, share):
        """ Set proctitle to contain sharename. """
        if config.use_api:
            return
        new_proctitle ="{proctitle} User: {username} Share: {share}"
        new_proctitle = new_proctitle.format(proctitle=self.proctitle,
                                            username=username,
                                            share=share)
        setproctitle.setproctitle(new_proctitle)

    def handle_share_setttings(self):
        while True:
            # Break on shutdown.
            if self.shutdown:
                break
            time.sleep(1)
            # No share set yet.
            if not self.share:
                continue

            try:
                hostd_conn = connections.get("hostd")
            except Exception:
                continue
            try:
                status, \
                response = hostd_conn.check_share_access(share_uuid=self.share_uuid,
                                                        host_uuid=self.peer.uuid,
                                                        token_uuid=config.auth_token.uuid)
            except Exception as e:
                log_msg = _("Share access check failed: {e}", log=True)[1]
                log_msg = log_msg.format(e=e)
                self.logger.warning(log_msg)
                continue

            if status:
                self.block_access = True
                log_msg = _("Share access denied: {response}", log=True)[1]
                log_msg = log_msg.format(response=response)
                self.logger.warning(log_msg)
                continue

            # Nothing more to do for restore shares.
            if self.restore_share:
                continue

            # Get share settings.
            try:
                self.directory_mode = response['directory_mode']
            except KeyError:
                pass
            try:
                self.create_mode = response['create_mode']
            except KeyError:
                pass
            try:
                self.read_only = response['read_only']
            except KeyError:
                pass

    def get_backupd_conn(self, host, home_dir=None, backup_key=None):
        try:
            backupd_conn = connections.get("backupd",
                                        node=host,
                                        timeout=3600,
                                        auto_auth=False,
                                        auto_preauth=True,
                                        encrypt_session=False,
                                        verify_preauth=False,
                                        backup_key=backup_key,
                                        backup_home_dir=home_dir,
                                        interactive=False)
        except Exception as e:
            msg, log_msg = _("Failed to get backup connection: {host_name}: {e}", log=True)
            msg = msg.format(host_name=host, e=e)
            log_msg = log_msg.format(host_name=host, e=e)
            self.logger.warning(log_msg)
            raise OTPmeException(msg) from e
        return backupd_conn

    def _process(self, command, command_args, binary_data):
        """ Handle fuse requests. """
        if config.use_api:
            if config.auth_token:
                self.username = config.auth_token.owner
                self.authenticated = True

        if not self.authenticated:
            message, log_msg = _("Please authenticate.", log=True)
            self.logger.warning(log_msg)
            status = status_codes.NEED_USER_AUTH
            response = {'try_other_node':False, 'message':message}
            return self.build_response(status, response)

        if self.block_access:
            message, log_msg = _("Permission denied.", log=True)
            self.logger.warning(log_msg)
            response = {'try_other_node':False, 'message':message}
            return self.build_response(False, response)

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
            message, log_msg = _("Unknown command: {command}", log=True)
            message = message.format(command=command)
            log_msg = log_msg.format(command=command)
            self.logger.warning(log_msg)
            status = False
            response = {'try_other_node':False, 'message':message}
            return self.build_response(status, response)

        status = True
        if command == "mount":
            if self.mounted:
                status = False
                message, log_msg = _("Share already mounted: {share}", log=True)
                message = message.format(share=self.share)
                log_msg = log_msg.format(share=self.share)
                self.logger.warning(log_msg)
                response = {'try_other_node':False, 'message':message}
                return self.build_response(status, response)
            try:
                self.home_share_enc_data = command_args['enc_home_data']
            except KeyError:
                pass
            try:
                self.share = command_args['share']
            except KeyError:
                status = status_codes.UNKNOWN_OBJECT
                message, log_msg = _("Missing share.", log=True)
                self.logger.warning(log_msg)
                response = {'try_other_node':False, 'message':message}
                return self.build_response(status, response)
            result = backend.search(object_type="share",
                                    attribute="name",
                                    value=self.share,
                                    realm=config.realm,
                                    site=config.site,
                                    return_type="instance")
            if not result:
                status = status_codes.UNKNOWN_OBJECT
                message, log_msg = _("Unknown share: {share}", log=True)
                message = message.format(share=self.share)
                log_msg = log_msg.format(share=self.share)
                self.logger.warning(log_msg)
                response = {'try_other_node':False, 'message':message}
                return self.build_response(status, response)
            share = result[0]
            self.share_uuid = share.uuid
            if not share.enabled:
                status = status_codes.PERMISSION_DENIED
                message, log_msg = _("Share disabled: {share}", log=True)
                message = message.format(share=self.share)
                log_msg = log_msg.format(share=self.share)
                self.logger.warning(log_msg)
                response = {'try_other_node':False, 'message':message}
                return self.build_response(status, response)
            self.home_share = share.home_share
            self.encrypted = share.encrypted
            if share.restore_share:
                self.restore_share = True
                restore_share = backend.get_object(uuid=share.restore_share)
                if not restore_share:
                    status = status_codes.UNKNOWN_OBJECT
                    message, log_msg = _("Restore share not found: {share}", log=True)
                    message = message.format(share=self.share)
                    log_msg = log_msg.format(share=self.share)
                    self.logger.warning(log_msg)
                    response = {'try_other_node':False, 'message':message}
                    return self.build_response(status, response)
                if share.limit_by_hosts:
                    if not share.is_assigned_host(host_uuid=self.peer.uuid,
                                                        include_groups=True,
                                                        include_roles=True):
                        status = status_codes.PERMISSION_DENIED
                        message, log_msg = _("No share permissions for this host: {share}", log=True)
                        message = message.format(share=self.share)
                        log_msg = log_msg.format(share=self.share)
                        self.logger.warning(log_msg)
                        response = {'try_other_node':False, 'message':message}
                        return self.build_response(status, response)
                if not share.is_assigned_token(token_uuid=config.auth_token.uuid):
                    status = status_codes.PERMISSION_DENIED
                    message, log_msg = _("No share permissions: {share}", log=True)
                    message = message.format(share=self.share)
                    log_msg = log_msg.format(share=self.share)
                    self.logger.warning(log_msg)
                    response = {'try_other_node':False, 'message':message}
                    return self.build_response(status, response)
                host = restore_share.get_config_parameter("backup_server")
                if not host:
                    status = status_codes.UNKNOWN_OBJECT
                    message, log_msg = _("Unable to find backup host for share: {share}", log=True)
                    message = message.format(share=self.share)
                    log_msg = log_msg.format(share=self.share)
                    self.logger.warning(log_msg)
                    response = {'try_other_node':False, 'message':message}
                    return self.build_response(status, response)
                self.encrypted = restore_share.encrypted
                # Get backup key
                backup_key = restore_share.get_config_parameter("backup_key")
                if not backup_key:
                    status = status_codes.UNKNOWN_OBJECT
                    message, log_msg = _("Unable to find backup key for share: {share}", log=True)
                    message = message.format(share=self.share)
                    log_msg = log_msg.format(share=self.share)
                    self.logger.warning(log_msg)
                    response = {'try_other_node':False, 'message':message}
                    return self.build_response(status, response)
                self.aes_key = bytes.fromhex(backup_key)

            # Get user groups.
            default_group = stuff.get_users_default_group(self.username)
            groups = stuff.get_users_groups(self.username)
            if self.restore_share:
                if share.force_group_uuid is not None:
                    group = backend.get_object(uuid=share.force_group_uuid)
                    if not group:
                        status = status_codes.UNKNOWN_OBJECT
                        message, log_msg = _("Unknown force group: {group_uuid}", log=True)
                        message = message.format(group_uuid=share.force_group_uuid)
                        log_msg = log_msg.format(group_uuid=share.force_group_uuid)
                        self.logger.warning(log_msg)
                        response = {'try_other_node':False, 'message':message}
                        return self.build_response(status, response)
                    if group.name not in groups:
                        status = status_codes.PERMISSION_DENIED
                        message, log_msg = _("Force group enabled and user not in group: {group_name}", log=True)
                        message = message.format(group_name=group.name)
                        log_msg = log_msg.format(group_name=group.name)
                        self.logger.warning(log_msg)
                        response = {'try_other_node':False, 'message':message}
                        return self.build_response(status, response)
                user_uuid = None
                if self.home_share:
                    user_uuid = config.auth_user.uuid
                repo_id = f"share/{restore_share.site}/{restore_share.name}"
                try:
                    self.backupd_conn = self.get_backupd_conn(host=host,
                                                            home_dir=user_uuid,
                                                            backup_key=backup_key)
                except Exception:
                    status = status_codes.BACKUP_CONNECTION_BROKEN
                    response = {'try_other_node':True, 'message':'Backupd connection failed.'}
                    return self.build_response(status, response)
                # Sign a short-lived mount JWT with our local site's
                # private key so backupd can prove the request came
                # from a legitimate OTPme daemon and no other client
                # can substitute username/groups/repository. The repo
                # password travels inside the signed payload so it is
                # tamper-proof end-to-end.
                backup_repo_password = restore_share.get_config_parameter("backup_repo_password")
                if not backup_repo_password:
                    status = status_codes.UNKNOWN_OBJECT
                    message, log_msg = _("Unable to find backup repo password for share: {share}", log=True)
                    message = message.format(share=self.share)
                    log_msg = log_msg.format(share=self.share)
                    self.logger.warning(log_msg)
                    response = {'try_other_node':False, 'message':message}
                    return self.build_response(status, response)
                mount_site = backend.get_object(object_type="site",
                                                uuid=config.site_uuid)
                if not mount_site or not mount_site._key:
                    status = status_codes.PERMISSION_DENIED
                    message, log_msg = _("Site JWT signing key missing: {site}", log=True)
                    message = message.format(site=config.site)
                    log_msg = log_msg.format(site=config.site)
                    self.logger.warning(log_msg)
                    response = {'try_other_node':False, 'message':message}
                    return self.build_response(status, response)
                now = time.time()
                mount_jwt_payload = {
                            'realm'         : config.realm,
                            'site'          : config.site,
                            'reason'        : 'BACKUP_MOUNT',
                            'repository'    : repo_id,
                            'username'      : self.username,
                            'default_group' : default_group,
                            'groups'        : groups,
                            'password'      : backup_repo_password,
                            'iat'           : now,
                            'exp'           : now + 60,
                        }
                mount_jwt = jwt.encode(payload=mount_jwt_payload,
                                       key=mount_site._key,
                                       algorithm='RS256')
                try:
                    self.backupd_conn.mount(repo_id,
                                            username=self.username,
                                            default_group=default_group,
                                            groups=groups,
                                            mount_jwt=mount_jwt)
                except Exception as e:
                    status = status_codes.BACKUP_CONNECTION_BROKEN
                    message, log_msg = _("Failed to mount restore share: {share_name}: {e}", log=True)
                    message = message.format(share_name=share.name, e=e)
                    log_msg = log_msg.format(share_name=share.name, e=e)
                    self.logger.warning(log_msg)
                    response = {'try_other_node':True, 'message':message}
                    return self.build_response(status, response)
                if self.encrypted:
                    try:
                        file_data = self.backupd_conn.read_cryptfs_settings()[1]
                    except Exception as e:
                        status = status_codes.BACKUP_CONNECTION_BROKEN
                        message, log_msg = _("Failed to read cryptfs settings from backup server: {share_name}: {e}", log=True)
                        message = message.format(share_name=share.name, e=e)
                        log_msg = log_msg.format(share_name=share.name, e=e)
                        self.logger.warning(log_msg)
                        response = {'try_other_node':True, 'message':message}
                        return self.build_response(status, response)
                    try:
                        file_data = file_data.decode()
                        lines = file_data.strip().split("\n")
                        chunk_hashes = [l for l in lines[2:] if l]
                        buf = b""
                        for h in chunk_hashes:
                            try:
                                blob = self.backupd_conn.get_chunk(h)[1]
                            except Exception as e:
                                status = status_codes.BACKUP_CONNECTION_BROKEN
                                message, log_msg = _("Failed to read cryptfs settings: {e}", log=True)
                                message = message.format(e=e)
                                log_msg = log_msg.format(e=e)
                                self.logger.warning(log_msg)
                                response = {'try_other_node':True, 'message':message}
                                return self.build_response(status, response)
                            # Decrypt and decompress.
                            flag, encrypted = blob[:1], blob[1:]
                            data = decrypt_block(self.aes_key, encrypted)
                            if flag == FLAG_ZLIB:
                                data = zlib.decompress(data)
                            buf += data
                    except Exception as e:
                        status = False
                        message, log_msg = _("Failed to decrypt cryptfs settings: {share_name}: {e}", log=True)
                        message = message.format(share_name=share.name, e=e)
                        log_msg = log_msg.format(share_name=share.name, e=e)
                        self.logger.warning(log_msg)
                        response = {'try_other_node':True, 'message':message}
                        return self.build_response(status, response)
                    try:
                        fs_data = load_cryptfs_settings(buf)
                    except Exception as e:
                        status = status_codes.UNKNOWN_OBJECT
                        message, log_msg = _("Failed to load cryptfs settings: {e}", log=True)
                        message = message.format(e=e)
                        log_msg = log_msg.format(e=e)
                        self.logger.warning(log_msg)
                        response = {'try_other_node':True, 'message':message}
                        return self.build_response(status, response)
            else:
                root_dir = share.root_dir
                if self.home_share:
                    root_dir = os.path.join(root_dir, config.auth_user.uuid)
                if not os.path.exists(share.root_dir):
                    status = status_codes.UNKNOWN_OBJECT
                    message, log_msg = _("Unknown share root dir: {share}: {root_dir}", log=True)
                    message = message.format(share=self.share, root_dir=share.root_dir)
                    log_msg = log_msg.format(share=self.share, root_dir=share.root_dir)
                    self.logger.warning(log_msg)
                    response = {'try_other_node':True, 'message':message}
                    return self.build_response(status, response)
                if share.limit_by_hosts:
                    if not share.is_assigned_host(host_uuid=self.peer.uuid,
                                                    include_groups=True,
                                                    include_roles=True):
                        status = status_codes.PERMISSION_DENIED
                        message, log_msg = _("No share permissions for this host: {share}", log=True)
                        message = message.format(share=self.share)
                        log_msg = log_msg.format(share=self.share)
                        self.logger.warning(log_msg)
                        response = {'try_other_node':False, 'message':message}
                        return self.build_response(status, response)
                if not share.is_assigned_token(token_uuid=config.auth_token.uuid) \
                and not share.is_master_password_token(config.auth_token.rel_path):
                    status = status_codes.PERMISSION_DENIED
                    message, log_msg = _("No share permissions: {share}", log=True)
                    message = message.format(share=self.share)
                    log_msg = log_msg.format(share=self.share)
                    self.logger.warning(log_msg)
                    response = {'try_other_node':False, 'message':message}
                    return self.build_response(status, response)
                if self.home_share:
                    if self.encrypted:
                        if not self.home_share_enc_data:
                            try:
                                fs_data = read_cryptfs_settings(path=root_dir)
                            except NotInitialized:
                                status = True
                                key_mode = config.auth_user.key_mode
                                response = {'command':'home_dir_enc', 'key_mode':key_mode, 'key_len':32}
                                return self.build_response(status, response)
                    if not os.path.exists(root_dir):
                        try:
                            filetools.create_dir(path=root_dir,
                                                user=config.auth_user.name,
                                                group=True,
                                                mode=0o700)
                        except Exception as e:
                            status = status_codes.ERR
                            message, log_msg = _("Failed to create home share dir: {e}", log=True)
                            message = message.format(e=e)
                            log_msg = log_msg.format(e=e)
                            self.logger.warning(log_msg)
                            response = {'try_other_node':False, 'message':message}
                            return self.build_response(status, response)
                try:
                    self.root = root_dir
                except Exception as e:
                    status = status_codes.UNKNOWN_OBJECT
                    message, log_msg = _("Failed to mount share: {share}", log=True)
                    message = message.format(share=share)
                    log_msg = log_msg.format(share=share)
                    log_msg = f"{log_msg}: {e}"
                    self.logger.warning(log_msg)
                    response = {'try_other_node':True, 'message':message}
                    return self.build_response(status, response)
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
                        response = {'try_other_node':True, 'message':message}
                        return self.build_response(status, response)
                if share.force_group_uuid is not None:
                    group = backend.get_object(uuid=share.force_group_uuid)
                    if not group:
                        status = status_codes.UNKNOWN_OBJECT
                        message, log_msg = _("Unknown force group: {group_uuid}", log=True)
                        message = message.format(group_uuid=share.force_group_uuid)
                        log_msg = log_msg.format(group_uuid=share.force_group_uuid)
                        self.logger.warning(log_msg)
                        response = {'try_other_node':False, 'message':message}
                        return self.build_response(status, response)
                    try:
                        self.force_group_gid = grp.getgrnam(group.name).gr_gid
                    except Exception:
                        status = status_codes.UNKNOWN_OBJECT
                        message, log_msg = _("Force group does not exists: {group_name}", log=True)
                        message = message.format(group_name=group.name)
                        log_msg = log_msg.format(group_name=group.name)
                        self.logger.warning(log_msg)
                        response = {'try_other_node':False, 'message':message}
                        return self.build_response(status, response)
                # Get share settings.
                self.read_only = share.read_only
                if share.directory_mode != "0o000":
                    self.directory_mode = int(share.directory_mode, 0)
                if share.create_mode != "0o000":
                    self.create_mode = int(share.create_mode, 0)
                if self.encrypted:
                    self.block_size = share.block_size
                    do_cryptfs_init = False
                    if self.home_share:
                        if self.home_share_enc_data:
                            try:
                                new_share_key = self.home_share_enc_data['share_key']
                            except KeyError:
                                status = False
                                message, log_msg = _("Request missses share key.", log=True)
                                self.logger.warning(log_msg)
                                response = {'try_other_node':False, 'message':message}
                                return self.build_response(status, response)
                            try:
                                hash_params = self.home_share_enc_data['hash_params']
                            except KeyError:
                                status = False
                                message, log_msg = _("Request missses hash parameters.", log=True)
                                self.logger.warning(log_msg)
                                response = {'try_other_node':False, 'message':message}
                                return self.build_response(status, response)
                            share.add_share_key(username=config.auth_user.name,
                                                share_key=new_share_key,
                                                callback=default_callback,
                                                verify_acls=False)
                            default_callback.write_modified_objects()
                            do_cryptfs_init = True
                    else:
                        do_cryptfs_init = True
                        hash_params = share.master_password_hash_params.copy()
                    if do_cryptfs_init:
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
                            response = {'try_other_node':False, 'message':message}
                            return self.build_response(status, response)
                    try:
                        fs_data = read_cryptfs_settings(path=self.root)
                    except NotInitialized:
                        status = status_codes.UNKNOWN_OBJECT
                        message, log_msg = _("Cryptfs not initialized: {root}", log=True)
                        message = message.format(root=self.root)
                        log_msg = log_msg.format(root=self.root)
                        self.logger.warning(log_msg)
                        response = {'try_other_node':False, 'message':message}
                        return self.build_response(status, response)
                    except Exception as e:
                        status = status_codes.UNKNOWN_OBJECT
                        message, log_msg = _("Failed to read cryptfs settings: {share_name}", log=True)
                        message = message.format(share_name=share.name)
                        log_msg = log_msg.format(share_name=share.name)
                        log_msg = f"{log_msg}: {e}"
                        self.logger.warning(log_msg)
                        response = {'try_other_node':False, 'message':message}
                        return self.build_response(status, response)
            if self.encrypted:
                try:
                    self.block_size = fs_data['block_size']
                except KeyError:
                    status = status_codes.UNKNOWN_OBJECT
                    message, log_msg = _("Cryptfs misses block size: {share_name}", log=True)
                    message = message.format(share_name=share.name)
                    log_msg = log_msg.format(share_name=share.name)
                    self.logger.warning(log_msg)
                    response = {'try_other_node':False, 'message':message}
                    return self.build_response(status, response)
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
                        response = {'try_other_node':False, 'message':message}
                        return self.build_response(status, response)
                    try:
                        master_password_hash_params = fs_data['hash_params']
                    except KeyError:
                        status = status_codes.UNKNOWN_OBJECT
                        message, log_msg = _("Cryptfs misses master password hash parameters: {share_name}", log=True)
                        message = message.format(share_name=share.name)
                        log_msg = log_msg.format(share_name=share.name)
                        self.logger.warning(log_msg)
                        response = {'try_other_node':False, 'message':message}
                        return self.build_response(status, response)
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
                        response = {'try_other_node':False, 'message':message}
                        return self.build_response(status, response)

            # Update last used time.
            share.update_last_used_time()
            mount_result = {}
            # Get share node FQDNs to reply.
            share_nodes = share.get_nodes(include_pools=True,
                                        return_type="instance")
            share_node_fqdns = []
            for node in share_nodes:
                share_node_fqdns.append(node.fqdn)
            mount_result = {'nodes':share_node_fqdns}
            # Handle non-restore shares stuff.
            if not self.restore_share:
                if not self.privileges_dropped:
                    if share.force_group_uuid is not None and self.username != "root":
                        if group.name not in groups:
                            status = status_codes.PERMISSION_DENIED
                            message, log_msg = _("Force group enabled and user not in group: {group_name}", log=True)
                            message = message.format(group_name=group.name)
                            log_msg = log_msg.format(group_name=group.name)
                            self.logger.warning(log_msg)
                            response = {'try_other_node':False, 'message':message}
                            return self.build_response(status, response)
                    try:
                        drop_privileges(user=self.username, group=default_group, groups=groups)
                    except Exception as e:
                        status = status_codes.PERMISSION_DENIED
                        message, log_msg = _("Failed to drop privileges: {error}", log=True)
                        message = message.format(error=e)
                        log_msg = log_msg.format(error=e)
                        self.logger.warning(log_msg)
                        response = {'try_other_node':False, 'message':message}
                        return self.build_response(status, response)
                    self.privileges_dropped = True
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
            message, log_msg = _("No share mounted.", log=True)
            self.logger.warning(log_msg)
            status = status_codes.UNKNOWN_OBJECT
            response = {'try_other_node':False, 'message':message}
            return self.build_response(status, False)

        if command == "add_share_key":
            try:
                share_key = command_args['share_key']
            except KeyError:
                status = status_codes.UNKNOWN_OBJECT
                message, log_msg = _("Missing share key.", log=True)
                self.logger.warning(log_msg)
                return self.build_response(status, message)
            if not self.mounted:
                message, log_msg = _("No share mounted.", log=True)
                self.logger.warning(log_msg)
                status = status_codes.UNKNOWN_OBJECT
                return self.build_response(status, message)
            if not self.encrypted:
                status = status_codes.UNKNOWN_OBJECT
                message, log_msg = _("Share not encrypted.", log=True)
                self.logger.warning(log_msg)
                return self.build_response(status, message)
            result = backend.search(object_type="share",
                                    attribute="name",
                                    value=self.share,
                                    realm=config.realm,
                                    site=config.site,
                                    return_type="instance")
            if not result:
                status = status_codes.UNKNOWN_OBJECT
                message, log_msg = _("Unknown share: {share}", log=True)
                message = message.format(share=self.share)
                log_msg = log_msg.format(share=self.share)
                self.logger.warning(log_msg)
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
            try:
                status, message = self.backupd_conn.exists(path)
            except Exception as e:
                status = status_codes.BACKUP_CONNECTION_BROKEN
                message, log_msg = _("Failed to run exists command: {e}", log=True)
                message = message.format(e=e)
                log_msg = log_msg.format(e=e)
                self.logger.warning(log_msg)
                response = {'try_other_node':True, 'message':message}
                return self.build_response(status, response)
            return self.build_response(status, message)

        elif command == "get_mtime":
            try:
                path = command_args['path']
            except KeyError:
                status = False
                message = _("Missing path.")
                return self.build_response(status, message)
            try:
                status, message = self.backupd_conn.get_mtime(path)
            except Exception as e:
                status = status_codes.BACKUP_CONNECTION_BROKEN
                message, log_msg = _("Failed to run get_mtime command: {e}", log=True)
                message = message.format(e=e)
                log_msg = log_msg.format(e=e)
                self.logger.warning(log_msg)
                response = {'try_other_node':True, 'message':message}
                return self.build_response(status, response)
            return self.build_response(status, message)

        elif command == "get_ctime":
            try:
                path = command_args['path']
            except KeyError:
                status = False
                message = _("Missing path.")
                return self.build_response(status, message)
            try:
                status, message = self.backupd_conn.get_ctime(path)
            except Exception as e:
                status = status_codes.BACKUP_CONNECTION_BROKEN
                message, log_msg = _("Failed to run get_ctime command: {e}", log=True)
                message = message.format(e=e)
                log_msg = log_msg.format(e=e)
                self.logger.warning(log_msg)
                response = {'try_other_node':True, 'message':message}
                return self.build_response(status, response)
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
                status, message = self.backupd_conn.access(path, amode)
            except Exception as e:
                status = status_codes.BACKUP_CONNECTION_BROKEN
                message, log_msg = _("Failed to run access command: {e}", log=True)
                message = message.format(e=e)
                log_msg = log_msg.format(e=e)
                self.logger.warning(log_msg)
                response = {'try_other_node':True, 'message':message}
                return self.build_response(status, response)
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
                status, message = self.backupd_conn.create(path, mode)
            except Exception as e:
                status = status_codes.BACKUP_CONNECTION_BROKEN
                message, log_msg = _("Failed to run create command: {e}", log=True)
                message = message.format(e=e)
                log_msg = log_msg.format(e=e)
                self.logger.warning(log_msg)
                response = {'try_other_node':True, 'message':message}
                return self.build_response(status, response)
            return self.build_response(status, message)

        elif command == "getattr":
            try:
                path = command_args['path']
            except KeyError:
                status = False
                message = _("Missing path.")
                return self.build_response(status, message)
            try:
                status, message = self.backupd_conn.getattr(path)
            except Exception as e:
                status = status_codes.BACKUP_CONNECTION_BROKEN
                message, log_msg = _("Failed to run getattr command: {e}", log=True)
                message = message.format(e=e)
                log_msg = log_msg.format(e=e)
                self.logger.warning(log_msg)
                response = {'try_other_node':True, 'message':message}
                return self.build_response(status, response)
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
                status, message = self.backupd_conn.link(target, source)
            except Exception as e:
                status = status_codes.BACKUP_CONNECTION_BROKEN
                message, log_msg = _("Failed to run link command: {e}", log=True)
                message = message.format(e=e)
                log_msg = log_msg.format(e=e)
                self.logger.warning(log_msg)
                response = {'try_other_node':True, 'message':message}
                return self.build_response(status, response)
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
                status, binary_data = self.restore_read(path, size, offset)
            except Exception as e:
                status = status_codes.BACKUP_CONNECTION_BROKEN
                message, log_msg = _("Failed to run restore_read command: {e}", log=True)
                message = message.format(e=e)
                log_msg = log_msg.format(e=e)
                self.logger.warning(log_msg)
                response = {'try_other_node':True, 'message':message}
                return self.build_response(status, response)
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
                status, message = self.backupd_conn.readdir(path)
            except Exception as e:
                status = status_codes.BACKUP_CONNECTION_BROKEN
                message, log_msg = _("Failed to run readdir command: {e}", log=True)
                message = message.format(e=e)
                log_msg = log_msg.format(e=e)
                self.logger.warning(log_msg)
                response = {'try_other_node':True, 'message':message}
                return self.build_response(status, response)
            return self.build_response(status, message)

        elif command == "readlink":
            try:
                path = command_args['path']
            except KeyError:
                status = False
                message = _("Missing path.")
                return self.build_response(status, message)
            try:
                status, message = self.backupd_conn.readlink(path)
            except Exception as e:
                status = status_codes.BACKUP_CONNECTION_BROKEN
                message, log_msg = _("Failed to run readlink command: {e}", log=True)
                message = message.format(e=e)
                log_msg = log_msg.format(e=e)
                self.logger.warning(log_msg)
                response = {'try_other_node':True, 'message':message}
                return self.build_response(status, response)
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
                status, message = self.backupd_conn.rename(old, new)
            except Exception as e:
                status = status_codes.BACKUP_CONNECTION_BROKEN
                message, log_msg = _("Failed to run rename command: {e}", log=True)
                message = message.format(e=e)
                log_msg = log_msg.format(e=e)
                self.logger.warning(log_msg)
                response = {'try_other_node':True, 'message':message}
                return self.build_response(status, response)
            return self.build_response(status, message)

        elif command == "statfs":
            try:
                path = command_args['path']
            except KeyError:
                status = False
                message = _("Missing path.")
                return self.build_response(status, message)
            try:
                status, message = self.backupd_conn.statfs(path)
            except Exception as e:
                status = status_codes.BACKUP_CONNECTION_BROKEN
                message, log_msg = _("Failed to run statfs command: {e}", log=True)
                message = message.format(e=e)
                log_msg = log_msg.format(e=e)
                self.logger.warning(log_msg)
                response = {'try_other_node':True, 'message':message}
                return self.build_response(status, response)
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
                status, message = self.backupd_conn.symlink(target, source)
            except Exception as e:
                status = status_codes.BACKUP_CONNECTION_BROKEN
                message, log_msg = _("Failed to run symlink command: {e}", log=True)
                message = message.format(e=e)
                log_msg = log_msg.format(e=e)
                self.logger.warning(log_msg)
                response = {'try_other_node':True, 'message':message}
                return self.build_response(status, response)
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
                status, message = self.backupd_conn.link(target, source)
            except Exception as e:
                status = status_codes.BACKUP_CONNECTION_BROKEN
                message, log_msg = _("Failed to run link command: {e}", log=True)
                message = message.format(e=e)
                log_msg = log_msg.format(e=e)
                self.logger.warning(log_msg)
                response = {'try_other_node':True, 'message':message}
                return self.build_response(status, response)
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
                status, message = self.backupd_conn.truncate(path, length)
            except Exception as e:
                status = status_codes.BACKUP_CONNECTION_BROKEN
                message, log_msg = _("Failed to run truncate command: {e}", log=True)
                message = message.format(e=e)
                log_msg = log_msg.format(e=e)
                self.logger.warning(log_msg)
                response = {'try_other_node':True, 'message':message}
                return self.build_response(status, response)
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
                status, message = self.backupd_conn.utimens(path, times)
            except Exception as e:
                status = status_codes.BACKUP_CONNECTION_BROKEN
                message, log_msg = _("Failed to run utimens command: {e}", log=True)
                message = message.format(e=e)
                log_msg = log_msg.format(e=e)
                self.logger.warning(log_msg)
                response = {'try_other_node':True, 'message':message}
                return self.build_response(status, response)
            return self.build_response(status, message)

        elif command == "unlink":
            try:
                path = command_args['path']
            except KeyError:
                status = False
                message = _("Missing path.")
                return self.build_response(status, message)
            try:
                status, message = self.backupd_conn.unlink(path)
            except Exception as e:
                status = status_codes.BACKUP_CONNECTION_BROKEN
                message, log_msg = _("Failed to run unlink command: {e}", log=True)
                message = message.format(e=e)
                log_msg = log_msg.format(e=e)
                self.logger.warning(log_msg)
                response = {'try_other_node':True, 'message':message}
                return self.build_response(status, response)
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
                status, message = self.backupd_conn.mkdir(path, mode)
            except Exception as e:
                status = status_codes.BACKUP_CONNECTION_BROKEN
                message, log_msg = _("Failed to run mkdir command: {e}", log=True)
                message = message.format(e=e)
                log_msg = log_msg.format(e=e)
                self.logger.warning(log_msg)
                response = {'try_other_node':True, 'message':message}
                return self.build_response(status, response)
            return self.build_response(status, message)

        elif command == "rmdir":
            try:
                path = command_args['path']
            except KeyError:
                status = False
                message = _("Missing path.")
                return self.build_response(status, message)
            try:
                status, message = self.backupd_conn.rmdir(path)
            except Exception as e:
                status = status_codes.BACKUP_CONNECTION_BROKEN
                message, log_msg = _("Failed to run rmdir command: {e}", log=True)
                message = message.format(e=e)
                log_msg = log_msg.format(e=e)
                self.logger.warning(log_msg)
                response = {'try_other_node':True, 'message':message}
                return self.build_response(status, response)
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
                status, message = self.backupd_conn.chmod(path, mode)
            except Exception as e:
                status = status_codes.BACKUP_CONNECTION_BROKEN
                message, log_msg = _("Failed to run chmod command: {e}", log=True)
                message = message.format(e=e)
                log_msg = log_msg.format(e=e)
                self.logger.warning(log_msg)
                response = {'try_other_node':True, 'message':message}
                return self.build_response(status, response)
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
                status, message = self.backupd_conn.chown(path, uid, gid)
            except Exception as e:
                status = status_codes.BACKUP_CONNECTION_BROKEN
                message, log_msg = _("Failed to run chown command: {e}", log=True)
                message = message.format(e=e)
                log_msg = log_msg.format(e=e)
                self.logger.warning(log_msg)
                response = {'try_other_node':True, 'message':message}
                return self.build_response(status, response)
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
                status, message = self.backupd_conn.write(path, binary_data, offset)
            except Exception as e:
                status = status_codes.BACKUP_CONNECTION_BROKEN
                message, log_msg = _("Failed to run write command: {e}", log=True)
                message = message.format(e=e)
                log_msg = log_msg.format(e=e)
                self.logger.warning(log_msg)
                response = {'try_other_node':True, 'message':message}
                return self.build_response(status, response)
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
                status, message = self.backupd_conn.open(path, flags)
            except Exception as e:
                status = status_codes.BACKUP_CONNECTION_BROKEN
                message, log_msg = _("Failed to run open command: {e}", log=True)
                message = message.format(e=e)
                log_msg = log_msg.format(e=e)
                self.logger.warning(log_msg)
                response = {'try_other_node':True, 'message':message}
                return self.build_response(status, response)
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
            try:
                status, binary_data = self.backupd_conn.getxattr(path, name, position)
            except Exception as e:
                status = status_codes.BACKUP_CONNECTION_BROKEN
                message, log_msg = _("Failed to run getxattr command: {e}", log=True)
                message = message.format(e=e)
                log_msg = log_msg.format(e=e)
                self.logger.warning(log_msg)
                response = {'try_other_node':True, 'message':message}
                return self.build_response(status, response)
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
            try:
                status, message = self.backupd_conn.setxattr(path, name, value, options, position)
            except Exception as e:
                status = status_codes.BACKUP_CONNECTION_BROKEN
                message, log_msg = _("Failed to run setxattr command: {e}", log=True)
                message = message.format(e=e)
                log_msg = log_msg.format(e=e)
                self.logger.warning(log_msg)
                response = {'try_other_node':True, 'message':message}
                return self.build_response(status, response)
            return self.build_response(status, message)

        elif command == "listxattr":
            try:
                path = command_args['path']
            except KeyError:
                status = False
                message = _("Missing path.")
                return self.build_response(status, message)
            try:
                status, message = self.backupd_conn.listxattr(path)
            except Exception as e:
                status = status_codes.BACKUP_CONNECTION_BROKEN
                message, log_msg = _("Failed to run listxattr command: {e}", log=True)
                message = message.format(e=e)
                log_msg = log_msg.format(e=e)
                self.logger.warning(log_msg)
                response = {'try_other_node':True, 'message':message}
                return self.build_response(status, response)
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
                status, message = self.backupd_conn.removexattr(path, name)
            except Exception as e:
                status = status_codes.BACKUP_CONNECTION_BROKEN
                message, log_msg = _("Failed to run removexattr command: {e}", log=True)
                message = message.format(e=e)
                log_msg = log_msg.format(e=e)
                self.logger.warning(log_msg)
                response = {'try_other_node':True, 'message':message}
                return self.build_response(status, response)
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

    def _close(self, *args, **kwargs):
        self.shutdown = True
        if not self.share_handler_thread:
            return
        self.share_handler_thread.join()

