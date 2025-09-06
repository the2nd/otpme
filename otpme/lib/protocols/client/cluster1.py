# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import oid
from otpme.lib import trash
from otpme.lib import config
from otpme.lib import backend
from otpme.lib.protocols import status_codes
from otpme.lib.protocols.otpme_client import OTPmeClient1

from otpme.lib.exceptions import *

REGISTER_BEFORE = []
REGISTER_AFTER = []
PROTOCOL_VERSION = "OTPme-cluster-1.0"

def register():
    config.register_otpme_protocol("clusterd", PROTOCOL_VERSION)

class OTPmeClusterP1(OTPmeClient1):
    """ Class that implements management client for protocol OTPme-cluster-1.0. """
    def __init__(self, **kwargs):
        self.daemon = "clusterd"
        self.name = PROTOCOL_VERSION
        # Get logger
        self.logger = config.logger
        super(OTPmeClusterP1, self).__init__(self.daemon, **kwargs)

    def ping(self):
        """ Send 'ping' command to clusterd. """
        command = "ping"
        command_args = {}
        status, \
        status_code, \
        reply, \
        binary_data = self.connection.send(command, command_args)
        return reply

    def write(self, object_id, object_config, index_journal=None,
        ldif_journal=None, acl_journal=None, full_acl_update=False,
        full_ldif_update=False, full_index_update=False,
        full_data_update=False, use_index_journal=True,
        use_acl_journal=True, use_ldif_journal=True,
        object_uuid=None, last_used=None):
        """ Send object to peer. """
        command = "write"
        command_args = {}
        command_args['object_id'] = object_id
        command_args['object_config'] = object_config
        command_args['acl_journal'] = acl_journal
        command_args['ldif_journal'] = ldif_journal
        command_args['index_journal'] = index_journal
        command_args['use_acl_journal'] = use_acl_journal
        command_args['use_ldif_journal'] = use_ldif_journal
        command_args['use_index_journal'] = use_index_journal
        command_args['full_acl_update'] = full_acl_update
        command_args['full_ldif_update'] = full_ldif_update
        command_args['full_data_update'] = full_data_update
        command_args['full_index_update'] = full_index_update
        command_args['object_uuid'] = object_uuid
        command_args['last_used'] = last_used
        status, \
        status_code, \
        reply, \
        binary_data = self.connection.send(command, command_args)
        if not status:
            msg = "Failed to send object: %s: %s" % (object_id, reply)
            raise OTPmeException(msg)
        return reply

    def object_exists(self, object_id):
        """ Check if object exists on peer. """
        command = "object_exists"
        command_args = {}
        command_args['object_id'] = object_id
        status, \
        status_code, \
        reply, \
        binary_data = self.connection.send(command, command_args)
        if not status:
            msg = "Failed to check if object exists: %s: %s" % (object_id, reply)
            if status_code == status_codes.NO_CLUSTER_SERVICE:
                raise NoClusterService(msg)
            raise OTPmeException(msg)
        return reply

    def delete(self, object_id, object_uuid):
        """ Delete object on peer. """
        command = "delete"
        command_args = {}
        command_args['object_id'] = object_id
        command_args['object_uuid'] = object_uuid
        status, \
        status_code, \
        reply, \
        binary_data = self.connection.send(command, command_args)
        if not status:
            msg = "Failed to delete object: %s: %s" % (object_id, reply)
            if status_code == status_codes.NO_CLUSTER_SERVICE:
                raise NoClusterService(msg)
            raise OTPmeException(msg)
        return reply

    def rename(self, object_id, new_object_id):
        """ Rename object on peer. """
        command = "rename"
        command_args = {}
        command_args['object_id'] = object_id
        command_args['new_object_id'] = new_object_id
        status, \
        status_code, \
        reply, \
        binary_data = self.connection.send(command, command_args)
        if not status:
            msg = "Failed to rename object: %s: %s" % (object_id, reply)
            raise OTPmeException(msg)
        return reply

    def acquire_lock(self, lock_type, lock_id, write):
        """ Acquire lock on peer. """
        command = "acquire_lock"
        command_args = {}
        command_args['lock_type'] = lock_type
        command_args['lock_id'] = lock_id
        command_args['write'] = write
        status, \
        status_code, \
        reply, \
        binary_data = self.connection.send(command, command_args)
        if not status:
            msg = "Failed to send lock request: %s: %s" % (lock_id, reply)
            raise LockWaitAbort(msg)
        return reply

    def release_lock(self, lock_id, write):
        """ Release lock on peer. """
        command = "release_lock"
        command_args = {}
        command_args['lock_id'] = lock_id
        command_args['write'] = write
        status, \
        status_code, \
        reply, \
        binary_data = self.connection.send(command, command_args)
        if not status:
            msg = ("Failed to send lock release request: %s: %s"
                    % (lock_id, reply))
            raise UnknownLock(msg)
        return reply

    def get_data_revision(self):
        """ Get data revision from peer. """
        command = "get_data_revision"
        command_args = {}
        status, \
        status_code, \
        reply, \
        binary_data = self.connection.send(command, command_args, timeout=None)
        if not status:
            msg = "Failed to get data revision: %s" % reply
            raise OTPmeException(msg)
        return reply

    def get_checksums(self):
        """ Get cluster checksums. """
        command = "get_checksums"
        command_args = {}
        status, \
        status_code, \
        reply, \
        binary_data = self.connection.send(command, command_args, timeout=None)
        if not status:
            msg = "Failed to get cluster checksums: %s" % reply
            raise OTPmeException(msg)
        return reply

    def get_full_checksums(self):
        """ Get cluster full checksums. """
        command = "get_full_checksums"
        command_args = {}
        status, \
        status_code, \
        reply, \
        binary_data = self.connection.send(command, command_args, timeout=None)
        if not status:
            msg = "Failed to get cluster checksums: %s" % reply
            raise OTPmeException(msg)
        return reply

    def get_index_checksums(self):
        """ Get cluster ndex checksums. """
        command = "get_index_checksums"
        command_args = {}
        status, \
        status_code, \
        reply, \
        binary_data = self.connection.send(command, command_args, timeout=None)
        if not status:
            msg = "Failed to get cluster checksums: %s" % reply
            raise OTPmeException(msg)
        return reply

    def trash_write(self, trash_id, object_id, object_data, deleted_by):
        """ Send trash object to peer. """
        command = "trash_write"
        command_args = {}
        command_args['trash_id'] = trash_id
        command_args['object_id'] = object_id
        command_args['object_data'] = object_data
        command_args['deleted_by'] = deleted_by
        status, \
        status_code, \
        reply, \
        binary_data = self.connection.send(command, command_args)
        if not status:
            msg = "Failed to send trash object: %s: %s" % (object_id, reply)
            raise OTPmeException(msg)
        return reply

    def trash_delete(self, trash_id):
        """ Send trash delete request to peer. """
        command = "trash_delete"
        command_args = {}
        command_args['trash_id'] = trash_id
        status, \
        status_code, \
        reply, \
        binary_data = self.connection.send(command, command_args)
        if not status:
            msg = "Failed to send trash delete request: %s: %s" % (trash_id, reply)
            raise OTPmeException(msg)
        return reply

    def trash_empty(self):
        """ Send trash empty request to peer. """
        command = "trash_empty"
        command_args = {}
        status, \
        status_code, \
        reply, \
        binary_data = self.connection.send(command, command_args)
        if not status:
            msg = "Failed to send trash empty request: %s" % reply
            raise OTPmeException(msg)
        return reply

    def last_used_write(self, object_type, objects):
        """ Send last used times to peer. """
        command = "last_used_write"
        command_args = {}
        command_args['object_type'] = object_type
        command_args['objects'] = objects
        status, \
        status_code, \
        reply, \
        binary_data = self.connection.send(command, command_args)
        if not status:
            msg = "Failed to send last used times: %s" % reply
            raise OTPmeException(msg)
        return reply

    def sync(self, skip_deletions=True):
        """ Sync data objects with peer. """
        object_types = config.get_cluster_object_types()
        return_attributes = ['full_oid', 'sync_checksum']
        result = backend.search(object_types=object_types,
                                attribute="uuid",
                                value="*",
                                return_attributes=return_attributes)
        local_objects = {}
        for x_uuid in result:
            x_oid = result[x_uuid]['full_oid']
            x_checksum = result[x_uuid]['sync_checksum']
            local_objects[x_oid] = {}
            local_objects[x_oid]['sync_checksum'] = x_checksum

        command = "sync"
        command_args = {'remote_objects':local_objects}
        status, \
        status_code, \
        reply, \
        binary_data = self.connection.send(command, command_args, timeout=None)
        if status_code == status_codes.NO_CLUSTER_QUORUM:
            raise OTPmeException(reply)
        if not status:
            raise OTPmeException(reply)
        synced_objects = []
        for x_oid in reply:
            x_oid = oid.get(x_oid)
            try:
                x_data = reply[x_oid]
            except KeyError:
                continue
            if not x_data:
                continue
            if hasattr(x_oid, "user_uuid"):
                if x_oid.user_uuid:
                    if not backend.get_oid(x_oid.user_uuid):
                        continue
            if hasattr(x_oid, "token_uuid"):
                if x_oid.token_uuid:
                    if not backend.get_oid(x_oid.token_uuid):
                        continue
            if hasattr(x_oid, "accessgroup_uuid"):
                if x_oid.accessgroup_uuid:
                    if not backend.get_oid(x_oid.accessgroup_uuid):
                        continue
            x_config = x_data['object_config']
            x_checksum = x_config['SYNC_CHECKSUM']
            msg = "Writing received object: %s (%s)" % (x_oid, x_checksum)
            self.logger.debug(msg)
            x_uuid = x_config['UUID']
            backend.write_config(x_oid,
                                object_config=x_config,
                                full_index_update=True,
                                full_data_update=True,
                                full_ldif_update=True,
                                full_acl_update=True,
                                cluster=False)
            synced_objects.append(x_oid)
        msg = ("Synced %s objects from peer: %s"
                % (len(synced_objects), self.peer.name))
        self.logger.info(msg)
        if skip_deletions:
            return reply
        # Remove deleted objects.
        for x_oid in local_objects:
            if x_oid in reply:
                continue
            x_oid = oid.get(x_oid)
            try:
                backend.delete_object(x_oid, cluster=False)
            except UnknownObject:
                pass
        return reply

    def sync_last_used(self):
        """ Sync last used times. """
        msg = "Syncing last used times..."
        self.logger.info(msg)
        object_types = config.get_cluster_object_types()
        # Get timestamps from peer.
        command = "get_last_used"
        command_args = {'object_types':object_types}
        status, \
        status_code, \
        remote_last_used, \
        binary_data = self.connection.send(command, command_args, timeout=None)
        local_last_used = backend.get_last_used_times(object_types)
        # Process last used timestamps from peer.
        for x_type in remote_last_used:
            if x_type not in object_types:
                msg = "Got not requested object type from peer: %s" % x_type
                self.logger.warning(msg)
                continue
            updates = {}
            for x_uuid in remote_last_used[x_type]:
                try:
                    timestamp = remote_last_used[x_type][x_uuid]
                except:
                    msg = "Remote last used data misses timestamp: %s" % x_uuid
                    self.logger.warning(msg)
                    continue
                try:
                    local_last_used_time = local_last_used[x_type][x_uuid]
                except:
                    local_last_used_time = 0.0
                if str(local_last_used_time) == str(timestamp):
                    continue
                updates[x_uuid] = timestamp
            # Finally set last used times.
            if updates:
                backend.set_last_used_times(x_type, updates)
        return True

    def sync_trash(self):
        """ Sync trash with peer. """
        command = "sync_trash"
        local_objects = trash.get_trash_data()
        command_args = {'remote_objects':local_objects}
        status, \
        status_code, \
        reply, \
        binary_data = self.connection.send(command, command_args, timeout=None)
        if status_code == status_codes.NO_CLUSTER_QUORUM:
            raise OTPmeException(reply)
        if not status:
            raise OTPmeException(reply)
        synced_objects = []
        for x_trash_id in reply:
            if reply[x_trash_id] is None:
                continue
            for x_oid in reply[x_trash_id]:
                msg = "Writing received trash object: %s (%s)" % (x_oid, x_trash_id)
                self.logger.debug(msg)
                x_object_data = reply[x_trash_id][x_oid]['object_data']
                x_deleted_by = reply[x_trash_id][x_oid]['deleted_by']
                try:
                    trash.write_entry(trash_id=x_trash_id,
                                    object_id=x_oid,
                                    object_data=x_object_data,
                                    deleted_by=x_deleted_by)
                except Exception as e:
                    msg = ("Failed to add trash entry: %s: %s: %s"
                                % (x_oid, x_trash_id, e))
                    self.logger.warning(msg)
                    config.raise_exception()
                else:
                    synced_objects.append(x_oid)
        # Remove deleted trash objects.
        for x_trash_id in local_objects:
            if x_trash_id in reply:
                continue
            try:
                trash.delete(trash_id=x_trash_id, cluster=False)
            except Exception as e:
                msg = "Failed to delete trash ID: %s: %s" % (x_trash_id, e)
                self.logger.warning(msg)
        msg = ("Synced %s trash objects from peer: %s"
                % (len(synced_objects), self.peer.name))
        self.logger.info(msg)
        return reply

    def deconfigure_floating_ip(self):
        """ Deconfigure floating IP. """
        command = "deconfigure_floating_ip"
        command_args = {}
        status, \
        status_code, \
        reply, \
        binary_data = self.connection.send(command, command_args, timeout=None)
        if not status:
            msg = "Failed to send deconfigure floating IP request: %s" % reply
            raise OTPmeException(msg)
        return reply

    def set_node_online(self):
        """ Mark node as online. """
        command = "set_node_online"
        command_args = {}
        status, \
        status_code, \
        reply, \
        binary_data = self.connection.send(command, command_args, timeout=None)
        return status

    def set_node_sync(self, sync_time):
        """ Mark node as in sync. """
        command = "set_node_sync"
        command_args = {'sync_time':sync_time}
        status, \
        status_code, \
        reply, \
        binary_data = self.connection.send(command, command_args, timeout=None)
        return status

    def unset_node_sync(self):
        """ Mark node as NOT in sync. """
        command = "unset_node_sync"
        command_args = {}
        status, \
        status_code, \
        reply, \
        binary_data = self.connection.send(command, command_args, timeout=None)
        return status

    def do_nsscache_sync(self):
        """ Do nsscache sync. """
        command = "do_nsscache_sync"
        command_args = {}
        status, \
        status_code, \
        reply, \
        binary_data = self.connection.send(command, command_args, timeout=None)
        return status

    def do_radius_reload(self):
        """ Do radius reload. """
        command = "do_radius_reload"
        command_args = {}
        status, \
        status_code, \
        reply, \
        binary_data = self.connection.send(command, command_args, timeout=None)
        return status

    def do_daemon_reload(self):
        """ Send daemon reload command. """
        command = "do_daemon_reload"
        command_args = {}
        status, \
        status_code, \
        reply, \
        binary_data = self.connection.send(command, command_args, timeout=None)
        return status

    def get_master_sync_status(self):
        """ Get node master sync status. """
        command = "get_master_sync_status"
        command_args = {}
        status, \
        status_code, \
        reply, \
        binary_data = self.connection.send(command, command_args, timeout=None)
        return status

    def get_node_sync_status(self):
        """ Get node sync status. """
        command = "get_node_sync_status"
        command_args = {}
        status, \
        status_code, \
        reply, \
        binary_data = self.connection.send(command, command_args, timeout=None)
        return status

    def get_cluster_status(self):
        """ Get cluster status. """
        command = "get_cluster_status"
        command_args = {}
        status, \
        status_code, \
        reply, \
        binary_data = self.connection.send(command, command_args, timeout=None)
        if not status:
            msg = "Failed to get cluster status: %s" % reply
            raise OTPmeException(msg)
        return reply

    def get_cluster_quorum(self):
        """ Get cluster quorum. """
        command = "get_cluster_quorum"
        command_args = {}
        status, \
        status_code, \
        reply, \
        binary_data = self.connection.send(command, command_args, timeout=None)
        if not status:
            msg = "Failed to get cluster quorum: %s" % reply
            raise OTPmeException(msg)
        return reply

    def get_node_vote(self):
        """ Get node vote. """
        command = "get_node_vote"
        command_args = {}
        status, \
        status_code, \
        reply, \
        binary_data = self.connection.send(command, command_args, timeout=None)
        if not status:
            msg = "Failed to get node vote: %s" % reply
            raise OTPmeException(msg)
        return reply

    def get_member_nodes(self):
        """ Get cluster member nodes. """
        command = "get_member_nodes"
        command_args = {}
        status, \
        status_code, \
        reply, \
        binary_data = self.connection.send(command, command_args, timeout=None)
        if not status:
            msg = "Failed to get cluster nodes: %s" % reply
            raise OTPmeException(msg)
        return reply

    def get_master_node(self):
        """ Get master node name. """
        command = "get_master_node"
        command_args = {}
        status, \
        status_code, \
        reply, \
        binary_data = self.connection.send(command, command_args, timeout=None)
        if not status:
            msg = "Failed to get master node."
            raise UnknownMasterNode(msg)
        return reply

    def set_required_votes(self, required_votes):
        """ Set cluster required node votes. """
        command = "set_required_votes"
        command_args = {'required_votes':required_votes}
        status, \
        status_code, \
        reply, \
        binary_data = self.connection.send(command, command_args, timeout=None)
        if not status:
            msg = "Failed to set required cluster votes: %s" % reply
            raise OTPmeException(msg)
        return reply

    def set_master_failover(self):
        """ Set master failover status. """
        command = "set_master_failover"
        command_args = {}
        status, \
        status_code, \
        reply, \
        binary_data = self.connection.send(command, command_args, timeout=None)
        if not status:
            msg = "Setting master failover status failed: %s" % reply
            raise OTPmeException(msg)
        return reply

    def start_master_failover(self):
        """ Do master failover on master mode. """
        command = "start_master_failover"
        command_args = {}
        status, \
        status_code, \
        reply, \
        binary_data = self.connection.send(command, command_args, timeout=None)
        if not status:
            raise OTPmeException(reply)
        return reply

    def get_master_failover_status(self):
        """ Do master failover. """
        command = "get_master_failover_status"
        command_args = {}
        status, \
        status_code, \
        reply, \
        binary_data = self.connection.send(command, command_args, timeout=None)
        return status

    def do_master_failover(self):
        """ Do master failover. """
        command = "do_master_failover"
        command_args = {}
        status, \
        status_code, \
        reply, \
        binary_data = self.connection.send(command, command_args, timeout=None)
        if not status:
            msg = "Master failover request failed: %s" % reply
            raise OTPmeException(msg)
        return reply
