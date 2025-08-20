# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time
import setproctitle

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import oid
from otpme.lib import json
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import locking
from otpme.lib import backend
from otpme.lib.humanize import units
from otpme.lib import multiprocessing
from otpme.lib.protocols import status_codes
from otpme.lib.classes.object_config import ObjectConfig
from otpme.lib.protocols.otpme_server import OTPmeServer1
from otpme.lib.classes.data_objects.token_counter import TokenCounter

from otpme.lib.exceptions import *

LOCK_TYPE = "sync.server"
REGISTER_BEFORE = []
REGISTER_AFTER = ['otpme.lib.protocols.otpme_server']
PROTOCOL_VERSION = "OTPme-sync-1.0"

def register():
    config.register_otpme_protocol("syncd", PROTOCOL_VERSION, server=True)
    locking.register_lock_type(LOCK_TYPE, module=__file__)

def add_sync_list_checksum(realm, site, peer_realm, peer_site, checksum,
    object_types=None, skip_admin=False, skip_users=None,
    skip_list=None, include_templates=False,
    include_uuids=None, sync_time=None):
    """ Update sync list checksum. """

    if sync_time is not None:
        sync_map = backend.get_sync_map(realm=realm,
                                        site=site,
                                        peer_realm=peer_realm,
                                        peer_site=peer_site)
        try:
            map_sync_time = sync_map['time']
        except:
            map_sync_time = 0
        if sync_time < map_sync_time:
            response = "Not updating sync list checksum due to time missmatch."
            return response

    update_type = "status"
    if checksum != config.SYNCING_STATUS_STRING:
        update_type = "checksum"
        # Get sync list checksum.
        sync_list, \
        sync_list_checksum = backend.get_sync_list(realm=realm,
                                                site=site,
                                                object_types=object_types,
                                                skip_list=skip_list,
                                                skip_users=skip_users,
                                                skip_admin=skip_admin,
                                                include_templates=include_templates,
                                                include_uuids=include_uuids,
                                                quiet=True)
    # Update checksum.
    backend.add_sync_map(realm=realm,
                        site=site,
                        peer_realm=peer_realm,
                        peer_site=peer_site,
                        checksum=checksum,
                        object_types=object_types)
    response = ("Updated %s in sync map: %s/%s: %s/%s: %s"
        % (update_type, peer_realm, peer_site, realm, site, checksum))
    return response

class OTPmeSyncP1(OTPmeServer1):
    """ Class that implements sync server for protocol OTPme-sync-1.0. """
    def __init__(self, **kwargs):
        # Our name.
        self.name = "syncd"
        # The protocol we support.
        self.protocol = PROTOCOL_VERSION
        # Indicates parent class that we need an authenticated host.
        self.require_auth = "host"
        self.require_preauth = True
        # Indicates parent class to require a client certificate.
        self.require_client_cert = True
        # Allow sync between nodes.
        self.require_master_node = False
        # Sync must be possible while master node failover.
        self.require_cluster_status = False
        # Sync parameters of peer.
        self.peer_sync_params = {}
        # Call parent class init.
        OTPmeServer1.__init__(self, **kwargs)

    def _pre_init(self, *args, **kwargs):
        """ Init protocol handler. """
        # Our PID.
        self.pid = os.getpid()
        # Do atfork stuff.
        multiprocessing.atfork(quiet=True)

    def get_site(self, realm, site):
        """ Get site object and all its objects needed to start a sync. """
        result = backend.search(realm=realm,
                                object_type="site",
                                attribute="name",
                                value=site,
                                return_type="instance")
        if not result:
            return

        site = result[0]

        # Realm master node must not send node from other site its own site.
        if config.realm_master_node:
            if self.peer.type == "node":
                if site.uuid != config.site_uuid:
                    if site.uuid == self.peer.site_uuid:
                        return

        site_objects = []
        add_realm = True

        # If our peer is from another realm we only need to send our own
        # realm.
        if self.peer.realm_uuid != config.realm_uuid:
            if site.realm_uuid != config.realm_uuid:
                add_realm = False

        # Only realm master nodes must send realm objects to other sites.
        if not config.realm_master_node:
            if self.peer.site_uuid != config.site_uuid:
                add_realm = False

        if add_realm:
            # Get sites realm object config.
            site_realm = backend.get_object(object_type="realm",
                                            uuid=site.realm_uuid)
            object_config = site_realm.get_sync_config(peer=self.peer)
            encoded_config = json.encode(object_config, encoding="hex")
            site_objects.append([site_realm.oid.full_oid, encoded_config])

        # Get sites object config.
        object_config = site.get_sync_config(peer=self.peer)
        encoded_config = json.encode(object_config, encoding="hex")
        site_objects.append([site.oid.full_oid, encoded_config])

        # Get all nodes.
        all_site_nodes = backend.search(object_type="node",
                                        attribute="uuid",
                                        value="*",
                                        realm=site.realm,
                                        site=site.name,
                                        return_type="instance")
        for node in all_site_nodes:
            object_config = node.get_sync_config(peer=self.peer)
            node_config = json.encode(object_config, encoding="hex")
            # Add node units.
            unit_uuid = node.unit_uuid
            while unit_uuid:
                unit = backend.get_object(object_type="unit", uuid=unit_uuid)
                object_config = unit.get_sync_config(peer=self.peer)
                encoded_config = json.encode(object_config, encoding="hex")
                site_objects.append([unit.oid.full_oid, encoded_config])
                unit_uuid = unit.unit_uuid
            # Add master node config.
            site_objects.append([node.oid.full_oid, node_config])

        return site_objects

    def get_local_token_data(self, token, data_type):
        """ Get local token used objects. """
        if data_type == "otp":
            local_objects = backend.search(object_type="used_otp",
                                        attribute="token_uuid",
                                        value=token.uuid,
                                        return_type="oid")
        if data_type == "counter":
            local_objects = backend.search(object_type="token_counter",
                                            attribute="token_uuid",
                                            value=token.uuid,
                                            return_type="oid")
        return local_objects

    def get_sites_command(self):
        """ Handle get_sites command. """
        offer_all_sites = False
        # Realm master node must offer all sites to any node.
        if config.realm_master_node:
            offer_all_sites = True

        # Master nodes must offer all sites to its non-master nodes.
        if config.master_node:
            if self.peer.site_uuid == config.site_uuid:
                offer_all_sites = True

        # If the peer node is from an other realm we just have to offer
        # sites from our own realm.
        realm = None
        if self.peer.realm_uuid != config.realm_uuid:
            realm = config.realm

        if offer_all_sites:
            sync_sites = backend.search(realm=realm,
                                    object_type="site",
                                    attribute="uuid",
                                    value="*",
                                    return_type="instance")
        else:
            own_site = backend.get_object(object_type="site",
                                        uuid=config.site_uuid)
            sync_sites = [own_site]

        object_configs = {}
        for x in sync_sites:
            # Get site and its master node to be synced.
            site_objects = self.get_site(realm=x.realm, site=x.name)
            if not site_objects:
                continue
            object_configs[x.oid.full_oid] = site_objects

        return object_configs

    def get_sync_list_command(self, realm, site, object_types,
        skip_list, skip_users, skip_admin, include_templates,
        include_uuids, sync_params):
        """ Handle get sync list command. """
        # Acquire sync lock.
        lock_id = "sync_objects:%s/%s" % (realm, site)
        sync_lock = locking.acquire_lock(lock_type=LOCK_TYPE, lock_id=lock_id)

        # Get sync list checksum.
        try:
            sync_list, \
            sync_list_checksum = backend.get_sync_list(realm=realm,
                                                    site=site,
                                                    object_types=object_types,
                                                    skip_list=skip_list,
                                                    skip_users=skip_users,
                                                    include_templates=include_templates,
                                                    include_uuids=include_uuids,
                                                    skip_admin=skip_admin,
                                                    quiet=True)
        finally:
            # Release sync lock.
            sync_lock.release_lock()
        # Build response.
        _sync_params = dict(sync_params)
        _sync_params['skip_admin'] = skip_admin
        _sync_params['skip_users'] = skip_users
        _sync_params['skip_list'] = skip_list
        _sync_params['include_uuids'] = include_uuids
        _sync_params['object_types'] = object_types
        _sync_params['include_templates'] = include_templates
        response = {
                    'sync_list'             : sync_list,
                    'sync_params'           : _sync_params,
                    'sync_list_checksum'    : sync_list_checksum,
                    }
        return response

    def add_sync_list_checksum_command(self, realm, site, object_types,
        skip_list, skip_users, skip_admin, include_templates,
        include_uuids, peer_checksum):
        """ Handle add sync list checksum command. """
        exception = None
        try:
            response = add_sync_list_checksum(realm=realm,
                                        site=site,
                                        peer_realm=self.peer.realm,
                                        peer_site=self.peer.site,
                                        object_types=object_types,
                                        checksum=peer_checksum,
                                        skip_admin=skip_admin,
                                        skip_users=skip_users,
                                        skip_list=skip_list,
                                        include_templates=include_templates,
                                        include_uuids=include_uuids)
        except Exception as e:
            exception = str(e)

        if exception:
            self.logger.warning(exception)
        else:
            self.logger.debug(response)
        return response

    def get_last_used_times(self, object_types):
        """ Handle get last used command. """
        # Get sync list.
        try:
            reply = backend.get_last_used_times(object_types=object_types)
            status = True
        except Exception as e:
            msg = "Failed to get last used data from backend: %s" % e
            self.logger.warning(msg)
            reply = "Failed to get last used data from backend."
            status = False
        return status, reply

    def get_object_command(self, object_id,
        valid_object_types, remote_checksums=None):
        """ Handle get object command. """
        status = True
        object_type = object_id.object_type
        # Check if a valid object is requested.
        if object_type not in valid_object_types:
            status = False
            response = "Permission denied: %s" % object_id
            self.logger.warning(response)
            return status, response
        if not backend.object_exists(object_id):
            status = status_codes.UNKNOWN_OBJECT
            response = "Unknown object: %s" % object_id
            self.logger.warning(response)
            # Hotfix our index.
            backend.index_del(object_id)
            return status, response
        # Get object.
        o = backend.get_object(object_type=object_type,
                                object_id=object_id)
        if not o:
            status = status_codes.UNKNOWN_OBJECT
            response = "Unknown object: %s" % object_id
            self.logger.warning(response)
            return status, response
        # Get sync object config.
        try:
            sync_config = o.get_sync_config(peer=self.peer)
        except Exception as e:
            response = ("Failed to get object sync config: %s: %s"
                        % (o.oid, e))
            status = False
            return status, response
        if remote_checksums:
            for attribute in sync_config:
                value = str(sync_config[attribute])
                local_checksum = stuff.gen_md5(value)
                try:
                    remote_checksum = remote_checksums[attribute]
                except:
                    remote_checksum = None
                if attribute != "CHECKSUM" and attribute != "SYNC_CHECKSUM":
                    if remote_checksum == local_checksum:
                        sync_config[attribute] = "USE_LOCAL"
        # Get UUID of parent object this object depends on.
        if o.type in config.tree_object_types:
            try:
                parent_object = o.get_parent_object()
            except:
                status = False
                response = "Unable to get parent object of: %s" % o
                self.logger.warning(response)
                return status, response
            sync_config['SYNC_PARENT_OBJECT_UUID'] = parent_object.uuid

        object_checksum = backend.get_sync_checksum(object_id)
        response = {'checksum':object_checksum,'object_config':sync_config}
        o_size = stuff.get_dict_size(sync_config)
        object_size = units.int2size(o_size)
        msg = ("Sending object (%s): %s"
            % (object_size, object_id))
        self.logger.debug(msg)
        return status, response

    def sync_token_data(self, data_type, remote_objects):
        """ Handle sync token data command. """
        sync_otps = False
        sync_counter = False

        if data_type == "otp":
            log_name = "used OTP"
            sync_otps = True

        if data_type == "counter":
            log_name = "token counter"
            sync_counter = True

        msg = "Reading %ss" % log_name
        self.logger.debug(msg)
        local_new_objects = []
        local_added_objects = []
        remote_new_objects = {}
        remote_outdated_objects = {}

        if sync_otps:
            local_objects = backend.search(object_type="used_otp",
                                        attribute="uuid",
                                        value="*",
                                        return_type="oid")
        if sync_counter:
            local_objects = backend.search(object_type="token_counter",
                                            attribute="uuid",
                                            value="*",
                                            return_type="oid")
        for x in remote_objects:
            x_oid = oid.get(object_id=x)
            x_config = remote_objects[x]
            # Decrypt object config..
            try:
                x_config = ObjectConfig(x_oid, x_config)
                x_config.decrypt()
                x_config.update_checksums(force=True)
            except Exception as e:
                msg = ("Failed to decrypt %s from peer: "
                    "%s: %s" % (log_name, self.peer.fqdn, x_oid))
                self.logger.critical(msg)
                continue
            try:
                x_object = TokenCounter(object_id=x_oid,
                                        object_config=x_config)
                x_object._load()
            except Exception as e:
                msg = "Failed to load token counter: %s: %s" % (x_oid, e)
                self.logger.critical(msg)
                continue
            # Handle remote outdated objects.
            remote_outdated_objects[x_oid.full_oid] = None
            # Make sure we got a valid token counter.
            if sync_counter:
                try:
                    int(x_object.counter)
                except Exception as e:
                    msg = ("Got invalid token counter from peer: "
                            "%s: %s: %s" % (self.peer.fqdn, x_oid, e))
                    self.logger.critical(msg)
                    continue
            # Make sure we got a valid OTP hash.
            if sync_otps:
                try:
                    if x_object.object_hash != x_oid.object_hash:
                        msg = (_("Got wrong OTP hash."))
                        raise OTPmeException(msg)
                except Exception as e:
                    msg = ("Got invalid OTP hash from peer: "
                            "%s: %s" % (self.peer.fqdn, x_oid))
                    self.logger.critical(msg)
                    continue

            if x_oid in local_objects:
                continue

            # Write object to backend.
            try:
                backend.write_config(x_oid, instance=x_object, cluster=True)
                local_added_objects.append(x_oid)
            except Exception as e:
                msg = ("Error writing config: %s: %s" % (x_oid, e))
                self.logger.critical(msg)

            # Get token.
            result = backend.search(object_type="token",
                                    attribute="uuid",
                                    value=x_object.token_uuid,
                                    return_type="instance")
            if not result:
                continue
            token = result[0]

            # Remove outdated objects.
            if sync_otps:
                # Call is_used_otp() with dummy OTP to get expired
                # OTPs removed.
                token.is_used_otp(otp="xxx")
            if sync_counter:
                # Call get_token_counter() with to get old counters
                # removed.
                token.get_token_counter()

        # Reload local objects after removing outdated objects.
        if sync_otps:
            local_objects = backend.search(object_type="used_otp",
                                        attribute="uuid",
                                        value="*",
                                        return_type="oid")
        if sync_counter:
            local_objects = backend.search(object_type="token_counter",
                                            attribute="uuid",
                                            value="*",
                                            return_type="oid")
        status = True
        for x_oid in local_objects:
            # Handle list of outdated objects.
            if x_oid.full_oid in remote_outdated_objects:
                remote_outdated_objects.pop(x_oid.full_oid)
            if x_oid in local_added_objects:
                local_new_objects.append(x_oid)
            if x_oid in remote_objects:
                continue
            # Get object config.
            x_config = backend.read_config(x_oid)
            if not x_config:
                msg = "Missing object: %s: Broken index?" % x_oid
                self.logger.warning(msg)
                continue
            # Encrypt object config.
            x_config = ObjectConfig(object_id=x_oid,
                                    object_config=x_config,
                                    encrypted=False)
            remote_new_objects[x_oid.full_oid] = x_config.copy()

        object_count = len(remote_new_objects)
        if object_count > 0:
            log_method = self.logger.info
        else:
            log_method = self.logger.debug
        log_method("Sending %s %ss" % (object_count, log_name))

        object_count = len(local_new_objects)
        if object_count > 0:
            log_method = self.logger.info
        else:
            log_method = self.logger.debug
        log_method("Added %s %ss" % (object_count, log_name))

        # Build response.
        response = {
                'new_objects'       : remote_new_objects,
                'outdated_objects'  : remote_outdated_objects,
                }
        return status, response

    def sync_offline_token_data(self, data_type,
        object_id, session_uuid, remote_objects):
        """ Handle sync offline token data command. """
        sync_otps = False
        sync_counter = False

        if data_type == "otp":
            log_name = "used OTP"
            sync_otps = True

        if data_type == "counter":
            log_name = "token counter"
            sync_counter = True

        token_oid = oid.get(object_id=object_id)
        try:
            token = backend.get_object(object_type="token",
                                    object_id=token_oid)
        except Exception as e:
            msg = (_("Unable to load token: %s") % token_oid)
            self.logger.critical(msg)
            status = False
            response = "SYNC_UNKNOWN_OBJECT: %s" % token_oid
            return status, response

        if token is None:
            msg = (_("Unknown token: %s") % token_oid)
            self.logger.critical(msg)
            status = False
            response = "SYNC_UNKNOWN_OBJECT: %s" % token_oid
            return status, response

        try:
            session = backend.get_object(uuid=session_uuid,
                                        object_type="session")
        except Exception as e:
            msg = (_("Unable to load session: %s") % session_uuid)
            self.logger.critical(msg)
            status = False
            response = "SYNC_FAILED_TO_LOAD_SESSION: %s" % session_uuid
            return status, response

        if not session:
            msg = (_("Unknown session: %s") % session_uuid)
            self.logger.critical(msg)
            status = status_codes.UNKNOWN_OBJECT
            response = "SYNC_UNKNOWN_SESSION: %s" % session_uuid
            return status, response

        offline_data_key = session.offline_data_key
        msg = ("Reading %ss: %s" % (log_name, token_oid))
        self.logger.debug(msg)
        local_new_objects = []
        local_added_objects = []
        remote_new_objects = {}
        remote_outdated_objects = {}

        # Get local objects.
        local_objects = self.get_local_token_data(token, data_type)

        for x in remote_objects:
            x_oid = oid.get(object_id=x)
            x_config = remote_objects[x]
            # Decrypt object config..
            try:
                x_config = ObjectConfig(x_oid, x_config)
                x_config.decrypt(key=offline_data_key)
                x_config.update_checksums(force=True)
            except Exception as e:
                msg = ("Failed to decrypt %s from peer: "
                    "%s: %s" % (log_name, self.peer.fqdn, x_oid))
                self.logger.critical(msg)
                continue
            try:
                x_object = TokenCounter(object_id=x_oid,
                                        object_config=x_config)
                x_object._load()
            except Exception as e:
                msg = "Failed to load token counter: %s: %s" % (x_oid, e)
                self.logger.critical(msg)
                continue
            # Handle remote outdated objects.
            remote_outdated_objects[x_oid.full_oid] = None
            # Make sure we got a valid token counter.
            if sync_counter:
                try:
                    int(x_object.counter)
                except Exception as e:
                    msg = ("Got invalid token counter from peer: "
                            "%s: %s: %s" % (self.peer.fqdn, x_oid, e))
                    self.logger.critical(msg)
                    continue
            # Make sure we got a valid OTP hash.
            if sync_otps:
                try:
                    if x_object.object_hash != x_oid.object_hash:
                        msg = (_("Got wrong OTP hash."))
                        raise OTPmeException(msg)
                except Exception as e:
                    msg = ("Got invalid OTP hash from peer: "
                            "%s: %s" % (self.peer.fqdn, x_oid))
                    self.logger.critical(msg)
                    continue

            if x_oid in local_objects:
                continue

            # Write object to backend.
            try:
                backend.write_config(x_oid, instance=x_object, cluster=True)
                local_added_objects.append(x_oid)
            except Exception as e:
                msg = ("Error writing config: %s: %s" % (x_oid, e))
                self.logger.critical(msg)

        # Remove outdated objects.
        if sync_otps:
            # Call is_used_otp() with dummy OTP to get expired
            # OTPs removed.
            token.is_used_otp(otp="xxx")
        if sync_counter:
            # Call get_token_counter() to get old counters
            # removed.
            token.get_token_counter()

        # Reload local objects after removing outdated objects.
        local_objects = self.get_local_token_data(token, data_type)

        status = True
        for x_oid in local_objects:
            # Handle list of outdated objects.
            if x_oid.full_oid in remote_outdated_objects:
                remote_outdated_objects.pop(x_oid.full_oid)
            if x_oid in local_added_objects:
                local_new_objects.append(x_oid)
            if x_oid in remote_objects:
                continue
            # Get object config.
            x_config = backend.read_config(x_oid)
            # Encrypt object config.
            x_config = ObjectConfig(object_id=x_oid,
                                    object_config=x_config,
                                    encrypted=False)
            x_config = x_config.encrypt(key=offline_data_key)
            remote_new_objects[x_oid.full_oid] = x_config.copy()

        object_count = len(remote_new_objects)
        if object_count > 0:
            log_method = self.logger.info
        else:
            log_method = self.logger.debug
        log_method("Sending %s %ss: %s"
                    % (object_count,
                    log_name,
                    token_oid))

        object_count = len(local_new_objects)
        if object_count > 0:
            log_method = self.logger.info
        else:
            log_method = self.logger.debug
        log_method("Added %s %ss: %s"
                    % (object_count,
                    log_name,
                    token_oid))

        # Build response.
        response = {
                'new_objects'       : remote_new_objects,
                'outdated_objects'  : remote_outdated_objects,
                }
        return status, response

    def get_authorized_keys_command(self):
        """ Handle get authorized keys command. """
        result = backend.search(object_type=self.peer.type,
                                attribute="name",
                                value=self.peer.name,
                                return_type="instance")
        if result:
            status = True
            host = result[0]
            auth_keys = host.get_ssh_authorized_keys()
            response = auth_keys
        else:
            status = False
            response = ("Unknown %s: %s" % (self.peer.type,
                                        self.peer.name))
            self.logger.warning(response)
        return status, response

    def start_sync_command(self):
        """ Handle start sync command. """
        from otpme.lib.classes.command_handler import CommandHandler
        if self.peer.type != "node":
            status = False
            response = (_("Invalid command for host type: %s")
                                % self.peer.type)
            self.logger.warning(response)
            return status, response
        # Get command handler.
        command_handler = CommandHandler(interactive=False)

        # Add sync sites command to queue.
        try:
            command_handler.start_sync(sync_type="sites")
        except Exception as e:
            msg = (_("Error queueing sync sites command: %s") % e)
            self.logger.warning(msg)

        # Get master site.
        master_site = backend.get_object(object_type="site",
                                uuid=config.realm_master_uuid)
        # Get own site.
        own_site = backend.get_object(object_type="site",
                                    uuid=config.site_uuid)

        # If we are the site master we have to sync only the site we
        # got notified from.
        if own_site.uuid == master_site.uuid:
            value = self.peer.site
        else:
            # Non-master nodes must sync all sites of their realm.
            value = "*"
        # Get sites to sync.
        sync_sites = backend.search(object_type="site",
                                    attribute="name",
                                    value=value,
                                    realm=config.realm,
                                    return_type="instance")
        response = []
        status = True
        sync_type = "objects"
        for site in sync_sites:
            msg = (_("Added sync command to queue: %s/%s (%s)")
                            % (site.realm, site.name, sync_type))
            # Check if we are already syncing.
            sync_status = config.get_sync_status(site.realm, site.name, sync_type)
            # Get data to build sync list.
            sync_params = self.peer.get_sync_parameters(site.realm,
                                                    site.name,
                                                    config.uuid)
            # Add current node time. This time is used to prevent
            # the master node from updating the sync status of
            # this node to "running" if the running sync finished
            # while this sync notify request is running.
            sync_params['time'] = time.time()
            # Add sync info.
            sync_params['status'] = sync_status
            sync_params['info'] = msg
            response.append(sync_params)
            # No need to start new sync if one is running.
            if sync_status == "running":
                continue
            # Add sync command to queue.
            try:
                command_handler.start_sync(sync_type=sync_type,
                                            resync=False,
                                            realm=site.realm,
                                            site=site.name)
            except Exception as e:
                msg = (_("Error queueing sync command: %s") % e)
                self.logger.warning(msg)
                status = False
                # Update sync info.
                sync_params['status'] = "failed"
                sync_params['info'] = msg
                break
            # Log add message.
            self.logger.info(msg)

        return status, response

    def _process(self, command, command_args, **kwargs):
        """ Handle sync data received from sync_handler. """
        # All valid commands.
        valid_commands = [
                        "start_sync",
                        "get_realms",
                        "get_sites",
                        "get_object",
                        "get_sync_list",
                        "get_last_used",
                        "get_sync_list_checksum",
                        "add_sync_list_checksum",
                        "get_ssh_authorized_keys",
                        "sync_offline_token_data",
                        "sync_token_data",
                        ]

        # Indicates if the command was successful.
        status = True
        response = ""

        # Check if we got a valid command.
        if not command in valid_commands:
            message = "Unknown command: %s" % command
            status = False
            return self.build_response(status, message)

        if not self.authenticated or not self.peer:
            message = "Please auth first."
            status = status_codes.NEED_HOST_AUTH
            return self.build_response(status, message)

        # Set proctitle to contain peer name.
        new_proctitle = "%s (%s)" % (self.proctitle, command)
        setproctitle.setproctitle(new_proctitle)

        # Check for quorum.
        if config.host_data['type'] == "node":
            if self.peer.type == "host":
                if not config.use_api:
                    if not config.cluster_quorum:
                        #status = status_codes.NO_CLUSTER_QUORUM
                        status = False
                        response = "No cluster quorum."
                        return self.build_response(status, response, encrypt=False)

        if command != "get_object":
            if config.debug_level() > 3:
                msg = ("Processing sync command: %s" % command)
                self.logger.debug(msg)

        # Check if sync with peer realm is disabled.
        peer_realm = backend.get_object(object_type="realm",
                                    uuid=self.peer.realm_uuid)
        if not peer_realm.sync_enabled:
            message = ("Synchronization disabled with realm: %s"
                        % peer_realm.name)
            status = status_codes.SYNC_DISABLED
            return self.build_response(status, message)

        # Check if sync with peer site is disabled.
        peer_site = backend.get_object(object_type="site",
                                    uuid=self.peer.site_uuid)
        if not peer_site.sync_enabled:
            message = ("Synchronization disabled with site: %s"
                        % peer_site.name)
            status = status_codes.SYNC_DISABLED
            return self.build_response(status, message)

        # Get sync realm/site.
        try:
            sync_realm = command_args['realm']
        except:
            sync_realm = config.realm
        try:
            sync_site = command_args['site']
        except:
            sync_site = config.site
        try:
            peer_skip_admin = command_args['skip_admin']
        except:
            peer_skip_admin = False
        try:
            peer_skip_users = command_args['skip_users']
        except:
            peer_skip_users = []
        try:
            peer_skip_list = command_args['skip_list']
        except:
            peer_skip_list = []

        if command == "start_sync":
            status, response = self.start_sync_command()
            return self.build_response(status, response)

        # Only realm/site master node is allowed to sync all sites to peer.
        if self.peer.type == "node" \
        and not config.master_node:
            if sync_realm != config.realm:
                response = "Permission denied: %s/%s" % (sync_realm, sync_site)
                self.logger.warning(response)
                status = status_codes.PERMISSION_DENIED
                return self.build_response(status, response)

            if sync_site != config.site:
                response = "Permission denied: %s/%s" % (sync_realm, sync_site)
                self.logger.warning(response)
                status = status_codes.PERMISSION_DENIED
                return self.build_response(status, response)

        # Get sync parameters of peer syncing with us.
        try:
            sync_params = self.peer_sync_params[self.peer.uuid][sync_realm][sync_site]
        except KeyError:
            # Cache sync parameters for peer to speedup processing.
            sync_params = self.peer.get_sync_parameters(sync_realm,
                                                        sync_site,
                                                        self.peer.uuid)
            if self.peer.uuid not in self.peer_sync_params:
                self.peer_sync_params[self.peer.uuid] = {}
            if sync_realm not in self.peer_sync_params[self.peer.uuid]:
                self.peer_sync_params[self.peer.uuid][sync_realm] = {}
            self.peer_sync_params[self.peer.uuid][sync_realm][sync_site] = sync_params

        skip_admin = sync_params['skip_admin']
        skip_users = sync_params['skip_users']
        skip_list = sync_params['skip_list']
        include_templates = sync_params['include_templates']
        sync_object_types = list(sync_params['object_types'])
        valid_object_types = list(sync_params['valid_object_types'])
        try:
            include_uuids = dict(sync_params['include_uuids'])
        except:
            include_uuids = None
        # Check admin user access.
        if peer_skip_admin:
            skip_admin = True
        else:
            if self.peer.type == "node" and skip_admin:
                admin_token = backend.get_object(uuid=config.admin_token_uuid)
                admin_user = backend.get_object(uuid=admin_token.owner_uuid)
                message = "Permission denied: %s" % admin_user.oid
                status = status_codes.PERMISSION_DENIED
                return self.build_response(status, message)
            skip_admin = False
        # Merge sync parameters.
        for x in peer_skip_users:
            if x in skip_users:
                continue
            skip_users.append(x)
        for x in peer_skip_list:
            if x in skip_list:
                continue
            skip_list.append(x)

        if command == "get_sites":
            try:
                response = self.get_sites_command()
                status = True
            except Exception as e:
                response = "Failed to get sites: %s" % e
                self.logger.warning(response)
                status = False
            return self.build_response(status, response)

        if command == "get_sync_list":
            response = self.get_sync_list_command(sync_realm,
                                                sync_site,
                                                sync_object_types,
                                                skip_list,
                                                skip_users,
                                                skip_admin,
                                                include_templates,
                                                include_uuids,
                                                sync_params)
            return self.build_response(status, response)

        if command == "add_sync_list_checksum":
            try:
                peer_checksum = command_args['checksum']
            except:
                status = False
                response = ("Missing peer checksum: add_sync_list_checksum: %s"
                        % self.peer)
                return self.build_response(status, response)

            try:
                object_types = command_args['object_types']
            except:
                object_types = None

            response = self.add_sync_list_checksum_command(sync_realm,
                                                            sync_site,
                                                            object_types,
                                                            skip_list,
                                                            skip_users,
                                                            skip_admin,
                                                            include_templates,
                                                            include_uuids,
                                                            peer_checksum)
            return self.build_response(status, response)

        if command == "get_object":
            try:
                object_id = command_args['object_id']
            except:
                response = "SYNC_INCOMPLETE_COMMAND: Missing object ID."
                status = False
                self.logger.warning(response)
                return self.build_response(status, response)

            object_id = oid.get(object_id=object_id)
            try:
                remote_checksums = command_args['object_checksums']
            except:
                remote_checksums = None

            status, response = self.get_object_command(object_id,
                                                    valid_object_types,
                                                    remote_checksums)
            return self.build_response(status, response)

        if command == "get_last_used":
            if self.peer.type != "node":
                response = "Permission denied."
                status = False
                self.logger.warning(response)
                return self.build_response(status, response)
            status, response = self.get_last_used_times(sync_object_types)
            return self.build_response(status, response)

        if command == "sync_offline_token_data":
            try:
                data_type = command_args['data_type']
            except:
                data_type = None
                response = "SYNC_INCOMPLETE_COMMAND: Missing data type."
                status = False
                self.logger.warning(response)
                return self.build_response(status, response)

            try:
                object_id = command_args['token_oid']
            except:
                response = "SYNC_INCOMPLETE_COMMAND: Missing object ID."
                status = False
                self.logger.warning(response)
                return self.build_response(status, response)

            try:
                session_uuid = command_args['session_uuid']
            except:
                session_uuid = None
                response = "SYNC_INCOMPLETE_COMMAND: Missing session UUID."
                status = False
                self.logger.warning(response)
                return self.build_response(status, response)

            try:
                remote_objects = command_args['remote_objects']
            except:
                remote_objects = None
                response = "SYNC_INCOMPLETE_COMMAND: Missing list with known OTPs."
                status = False
                self.logger.warning(response)
                return self.build_response(status, response)

            status, response = self.sync_offline_token_data(data_type,
                                                            object_id,
                                                            session_uuid,
                                                            remote_objects)
            return self.build_response(status, response)

        if command == "sync_token_data":
            try:
                data_type = command_args['data_type']
            except:
                data_type = None
                response = "SYNC_INCOMPLETE_COMMAND: Missing data type."
                status = False
                self.logger.warning(response)
                return self.build_response(status, response)

            try:
                remote_objects = command_args['remote_objects']
            except:
                remote_objects = None
                response = "SYNC_INCOMPLETE_COMMAND: Missing list with known OTPs."
                status = False
                self.logger.warning(response)
                return self.build_response(status, response)

            status, response = self.sync_token_data(data_type, remote_objects)
            return self.build_response(status, response)

        if command == "get_ssh_authorized_keys":
            try:
                status, response = self.get_authorized_keys_command()
            except Exception as e:
                status = False
                response = "Failed to get SSH authorized keys: %s" % e
            return self.build_response(status, response)

    def _close(self):
        pass
