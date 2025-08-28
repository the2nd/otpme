# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import sys
import time
import setproctitle

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import oid
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import locking
from otpme.lib import nsscache
from otpme.lib import sign_key_cache
from otpme.lib import multiprocessing
from otpme.lib.sync_cache import SyncCache
from otpme.lib.protocols import status_codes
from otpme.lib.progress import ProgressCounter
from otpme.lib.protocols.otpme_client import OTPmeClient1

from otpme.lib.exceptions import *

LOCK_TYPE = "sync.client"

REGISTER_BEFORE = []
REGISTER_AFTER = []
PROTOCOL_VERSION = "OTPme-sync-1.0"

def register():
    config.register_otpme_protocol("syncd", PROTOCOL_VERSION)
    locking.register_lock_type(LOCK_TYPE, module=__file__)

def get_own_realm_site():
    own_host = backend.get_object(uuid=config.uuid)
    if not own_host:
        msg = "Unknown host: %s" % config.uuid
        raise OTPmeException(msg)
    return (own_host.realm, own_host.site)

def validate_received_object(src_site, o):
    """ Make sure its save to write the given object on this node. """
    own_realm, own_site = get_own_realm_site()
    # Get object data.
    object_id = o.oid
    object_type = o.type
    object_realm = o.realm
    object_site = o.site
    # Verify realm objects.
    if object_type == "realm":
        object_name = o.name
        # Make sure the received realm matches the sites realm.
        if object_name != src_site.realm:
            msg = ("Uuuh, received wrong realm for site: %s: %s"
                    % (src_site, object_id))
            raise OTPmeException(msg)
        # Realm-master nodes should never receive their own realm.
        if config.realm_master_node:
            if object_name == own_realm:
                msg = ("Uuuh remote site sent us our own realm.")
                raise OTPmeException(msg)
        return
    # Verify site objects.
    if object_type == "site":
        object_name = o.name
        # Make sure the received sites realm matches the source sites realm.
        if object_realm != src_site.realm:
            msg = ("Uuuh, received site from wrong realm from site: %s: %s"
                    % (src_site, object_id))
            raise OTPmeException(msg)
        # Site-master nodes should never receive their own site object.
        if config.master_node:
            if object_realm == own_realm \
            and object_name == own_site:
                msg = ("Uuuh remote site sent us our own site.")
                raise OTPmeException(msg)
        return
    # Make sure the received object is from the right realm/site.
    if object_realm != src_site.realm:
        msg = ("Uuuh received object from wrong realm from site: "
                "%s: %s" % (src_site, object_id))
        raise OTPmeException(msg)
    if object_site != src_site.name:
        msg = ("Uuuh, received object from wrong site from site: "
                "%s: %s" % (src_site, object_id))
        raise OTPmeException(msg)

class OTPmeSyncP1(OTPmeClient1):
    """ Class that implements sync client for protocol OTPme-sync-1.0. """
    def __init__(self, **kwargs):
        self.daemon = "syncd"
        self.name = PROTOCOL_VERSION
        # Get logger.
        self.logger = config.logger
        # Get host type we run on.
        self.host_type = config.host_data['type']
        # Mass add childs.
        self.mass_add_procs = {}
        # Sync progress.
        self.sync_progress = {}
        self.failed_objects = multiprocessing.get_list()
        self.synced_objects = multiprocessing.get_list()
        self.removed_objects = multiprocessing.get_list()
        self.blacklisted_users = multiprocessing.get_list()
        self.last_sync_status_update = 0.0
        super(OTPmeSyncP1, self).__init__(self.daemon, **kwargs)

    def update_sync_progress(self, realm, site, sync_type, object_count=0):
        """ Update sync progress. """
        try:
            x_counter = self.sync_progress[realm][site][sync_type]
        except:
            x_counter = None

        if x_counter is None:
            if object_count == 0:
                msg = (_("Need <object_count> on first call."))
                raise OTPmeException(msg)
            x_counter = ProgressCounter(object_count)
        elif object_count > 0:
            x_counter.add_counter(object_count)
            return

        last_update_age = time.time() - self.last_sync_status_update
        if last_update_age >= 3:
            self.last_sync_status_update = time.time()
            # Set sync status. If progress is 0, sync start time gets set.
            config.update_sync_status(realm=realm,
                                    site=site,
                                    status="running",
                                    sync_type=sync_type,
                                    progress=x_counter.progress)
        # Increase counter.
        x_counter.count()

        if not realm in self.sync_progress:
            self.sync_progress[realm] = {}
        if not site in self.sync_progress[realm]:
            self.sync_progress[realm][site] = {}

        self.sync_progress[realm][site][sync_type] = x_counter

    def send_sync_list_checksum(self, realm, site, sync_params,
        object_types=None, checksum=None):
        """ Try to update sync list checksum on peer node. """
        try_count = 0
        max_tries = 3
        command_args = {
                    'realm'         : realm,
                    'site'          : site,
                    'checksum'      : checksum,
                    }
        command_args.update(sync_params)
        msg = "Updating sync list checksum on peer node: %s" % checksum
        self.logger.debug(msg)
        while try_count < max_tries:
            status, \
            status_code, \
            reply, \
            binary_data = self.connection.send("add_sync_list_checksum", command_args)

            if status_code == status_codes.PERMISSION_DENIED:
                msg = ("Permission denied: %s/%s" % (realm, site))
                raise PermissionDenied(msg)
            if status_code == status_codes.SYNC_DISABLED:
                msg = ("Peer site disabled synchronization with us: %s/%s"
                        % (realm, site))
                raise SyncDisabled(msg)
            if status:
                return reply
            try_count += 1
            msg =("Error sending sync list checksum to peer: %s" % reply)
            self.logger.error(msg)
            msg = ("Retrying (%s/%s)" % (try_count, max_tries))
            self.logger.error(msg)
            time.sleep(1)

    def get_remote_sync_list(self, realm, site, sync_params):
        """ Try to get remote sync list. """
        try_count = 0
        max_tries = 3
        command_args = {
                    'realm'             : realm,
                    'site'              : site,
                    }
        command_args.update(sync_params)
        self.logger.debug("Requesting sync list from peer.")
        while try_count < max_tries:
            status, \
            status_code, \
            reply, \
            binary_data = self.connection.send("get_sync_list", command_args)
            if status_code == status_codes.PERMISSION_DENIED:
                msg = ("Permission denied: %s/%s" % (realm, site))
                raise PermissionDenied(msg)
            if status_code == status_codes.SYNC_DISABLED:
                msg = ("Peer site disabled synchronization with us: %s/%s"
                        % (realm, site))
                raise SyncDisabled(msg)
            if status:
                return reply
            try_count += 1
            msg = ("Error receiving sync list from peer: %s" % reply)
            self.logger.error(msg)
            msg = ("Retrying (%s/%s)" % (try_count, max_tries))
            self.logger.error(msg)
            time.sleep(1)

    def get_last_used_timestamps(self, sync_params):
        """ Try to get last used timestamps from remote. """
        try_count = 0
        max_tries = 3
        command_args = {}
        command_args.update(sync_params)
        self.logger.debug("Requesting last used timestamps from peer.")
        while True:
            status, \
            status_code, \
            reply, \
            binary_data = self.connection.send("get_last_used", command_args)
            if status_code == status_codes.PERMISSION_DENIED:
                msg = "Permission denied."
                raise PermissionDenied(msg)
            if status_code == status_codes.SYNC_DISABLED:
                msg = "Peer site disabled synchronization with us."
                raise SyncDisabled(msg)
            if status:
                return reply
            try_count += 1
            msg = ("Error receiving last used timestamps from peer: %s" % reply)
            self.logger.error(msg)
            msg = ("Retrying (%s/%s)" % (try_count, max_tries))
            self.logger.error(msg)

            if try_count >= max_tries:
                msg = "Failed to receive last used timestamps from peer."
                raise OTPmeException(msg)
            time.sleep(1)

    def sync_last_used(self, realm, site):
        # Acquire sync lock.
        lock_id = "sync_last_used:%s/%s" % (realm, site)
        sync_lock = locking.acquire_lock(lock_type=LOCK_TYPE, lock_id=lock_id)
        try:
            result = self._sync_last_used(realm, site)
        finally:
            sync_lock.release_lock()
        # Update sync status.
        config.update_sync_status(realm=realm,
                                site=site,
                                status=result,
                                sync_type="last_used")
        return result

    def _sync_last_used(self, realm, site):
        """ Sync last used times. """
        msg = "Syncing last used times..."
        self.logger.info(msg)
        # Get sync parameters.
        this_host = backend.get_object(uuid=config.uuid)
        sync_params = this_host.get_sync_parameters(realm, site, self.connection.peer.uuid)
        sync_object_types = sync_params['object_types']
        # Get timestamps from peer.
        remote_last_used = self.get_last_used_timestamps(sync_params=sync_params)
        # Count objects.
        object_count = 0
        for x_type in remote_last_used:
            object_count += len(remote_last_used[x_type])
        # Update progress.
        self.update_sync_progress(realm=realm,
                                site=site,
                                sync_type="last_used",
                                object_count=object_count)
        local_last_used = backend.get_last_used_times(sync_object_types)
        # Process last used timestamps from peer.
        for x_type in remote_last_used:
            if x_type not in sync_object_types:
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
                # Update progress.
                self.update_sync_progress(realm=realm,
                                        site=site,
                                        sync_type="last_used")
                # Get attributes to verify
                return_attrs = ['realm', 'site']
                x_attrs = backend.search(object_type=x_type,
                                        attribute="uuid",
                                        value=x_uuid,
                                        return_attributes=return_attrs)
                if not x_attrs:
                    msg = "Got unknown UUID from peer: %s" % x_uuid
                    self.logger.warning(msg)
                    continue
                x_realm = x_attrs[x_uuid]['realm']
                if x_realm != realm:
                    msg = ("Got UUID for not requested realm: %s: %s"
                            % (x_realm, x_uuid))
                    self.logger.warning(msg)
                    continue
                x_site = x_attrs[x_uuid]['site']
                if x_site != site:
                    msg = ("Got UUID for not requested site: %s: %s"
                            % (x_site, x_uuid))
                    self.logger.warning(msg)
                    continue
                updates[x_uuid] = timestamp
            # Finally set last used times.
            if updates:
                backend.set_last_used_times(x_type, updates)
        return True

    def sync_objects(self, realm, site, resync=False, max_tries=5,
        skip_object_deletion=True, sync_last_used=False,
        sync_older_objects=False, ignore_changed_objects=False):
        own_realm, own_site = get_own_realm_site()
        # Acquire sync lock.
        lock_id = "sync_objects:%s/%s" % (realm, site)
        sync_lock = locking.acquire_lock(lock_type=LOCK_TYPE, lock_id=lock_id)
        try:
            result = self._sync_objects(realm, site,
                                resync=resync, max_tries=max_tries,
                                sync_older_objects=sync_older_objects,
                                skip_object_deletion=skip_object_deletion,
                                ignore_changed_objects=ignore_changed_objects)
        finally:
            sync_lock.release_lock()
        # Update sync status.
        config.update_sync_status(realm=realm,
                                site=site,
                                status=result,
                                sync_type="objects")
        # Sync object last used timestamps.
        if sync_last_used:
            if result is not False:
                if self.connection.peer:
                    if self.connection.peer.realm == own_realm \
                    and self.connection.peer.site == own_site:
                        self.sync_last_used(realm, site)
        return result

    def _sync_objects(self, realm, site, resync=False, max_tries=5,
        sync_older_objects=False, ignore_changed_objects=False,
        skip_object_deletion=True):
        """ Sync objects with peer. """
        exit_status = True
        received_objects = 0
        sync_success = False

        start_msg = ("Checking for orphan sync cache %s/%s..." % (realm, site))
        if self.connection:
            start_msg = ("Starting sync of %s/%s (%s)"
                        % (realm, site, self.connection.socket_uri))
        self.logger.info(start_msg)

        if not config.master_key:
            msg = "Missing AES master key. Unable to start sync."
            self.logger.critical(msg)
            raise Exception(msg)

        # Our on-disk sync cache (e.g. from last failed sync).
        self.sync_cache = SyncCache(realm=realm, site=site,
                                    protocol=self.name,
                                    mem_cache=config.sync_mem_cache)
        # Load sync cache
        self.sync_cache.load()

        # Try to merge sync cache if we got no connection.
        if self.connection is None:
            # If there is no sync cache and no connection there was no
            # successful sync.
            if not self.sync_cache.remote_sync_list:
                return False
            remote_object_count = len(self.sync_cache.remote_sync_list) * 2
            self.update_sync_progress(realm=realm,
                                    site=site,
                                    sync_type="objects",
                                    object_count=remote_object_count)
            self.merge_sync_cache(realm, site,
                    sync_older_objects=sync_older_objects,
                    skip_object_deletion=skip_object_deletion)
            self.sync_cache.clear()
            return

        # Get data to build sync list.
        this_host = backend.get_object(uuid=config.uuid)
        sync_params = this_host.get_sync_parameters(realm, site, self.connection.peer.uuid)

        # Try to get sync list checksum and sync paramerters from peer.
        try:
            sync_list_response = self.get_remote_sync_list(realm=realm,
                                                        site=site,
                                                        sync_params=sync_params)
        except PermissionDenied:
            # Pass on exception to calling method.
            raise
        except SyncDisabled:
            # Pass on exception to calling method.
            raise
        except OTPmeException as e:
            self.logger.critical("Error getting remote sync list: %s" % e)
            return False
        # Get sync parameters from response.
        sync_params = sync_list_response['sync_params']
        skip_list = sync_params['skip_list']
        skip_admin = sync_params['skip_admin']
        skip_users = sync_params['skip_users']
        sync_object_types = sync_params['object_types']
        include_templates = sync_params['include_templates']
        remote_sync_list = sync_list_response['sync_list']
        remote_sync_list_checksum = sync_list_response['sync_list_checksum']
        try:
            include_uuids = sync_params['include_uuids']
        except:
            include_uuids = None
        try:
            checksum_only_types= sync_params['checksum_only_types']
        except:
            checksum_only_types = None
        # Set sync parameters to cache.
        self.sync_cache.sync_parameters = sync_params

        # Get local sync list and checksum.
        local_sync_list, \
        local_sync_list_checksum = backend.get_sync_list(realm=realm,
                                        site=site,
                                        skip_list=skip_list,
                                        skip_users=skip_users,
                                        skip_admin=skip_admin,
                                        include_templates=include_templates,
                                        include_uuids=include_uuids,
                                        object_types=sync_object_types,
                                        checksum_only_types=checksum_only_types,
                                        quiet=True)
        if resync:
            local_sync_list = []
            remote_sync_list_checksum = "RESYNC"

        # Do not enter while loop below if we are in sync with remote site.
        if local_sync_list_checksum == remote_sync_list_checksum:
            try_count = 0
            max_tries = 0
        else:
            try_count = 0
            # Get sync list to calculate progress stuff.
            try:
                sync_list_response = self.get_remote_sync_list(realm=realm,
                                                            site=site,
                                                            sync_params=sync_params)
            except PermissionDenied:
                # Pass on exception to calling method.
                raise
            except SyncDisabled:
                # Pass on exception to calling method.
                raise
            except Exception as e:
                self.logger.critical("Error getting remote sync list: %s" % e)
                config.raise_exception()
                return False
            remote_sync_list = sync_list_response['sync_list']
            # We loop two times over the remote object list. So we need to add
            # this to the progress calculation.
            remote_object_count = len(remote_sync_list) * 2
            self.update_sync_progress(realm=realm,
                                    site=site,
                                    sync_type="objects",
                                    object_count=remote_object_count)
            # Mark ourself as currently "syncing".
            try:
                self.send_sync_list_checksum(realm=realm,
                                            site=site,
                                            sync_params=sync_params,
                                            checksum=config.SYNCING_STATUS_STRING)
            except PermissionDenied:
                # Pass on exception to calling method.
                raise
            except SyncDisabled:
                # Pass on exception to calling method.
                raise
            except Exception as e:
                self.logger.critical("Error sending sync list to peer: %s" % e)
                config.raise_exception()
                return False

        changed_object = False
        while try_count < max_tries:
            try_count += 1
            msg = ("Config checksums differ: local=%s remote=%s"
                % (local_sync_list_checksum, remote_sync_list_checksum))
            self.logger.info(msg)
            msg = ("Starting sync try %s/%s" % (try_count, max_tries))
            self.logger.info(msg)

            # Get new remote sync list. The first call is done outsite this loop
            # because we need to know how many remote objects we will handle to
            # calculate a proper progress.
            if try_count > 1:
                try:
                    sync_list_response = self.get_remote_sync_list(realm=realm,
                                                                site=site,
                                                                sync_params=sync_params)
                except PermissionDenied:
                    # Pass on exception to calling method.
                    raise
                except SyncDisabled:
                    # Pass on exception to calling method.
                    raise
                except Exception as e:
                    self.logger.critical("Error getting remote sync list: %s" % e)
                    config.raise_exception()
                    return False
            remote_sync_list = sync_list_response['sync_list']

            self.logger.info("Syncing remote objects...")

            # Get objects to be synced.
            object_count = 0
            _sync_objects = {}
            for object_id in sorted(remote_sync_list):
                # Get checksum.
                remote_checksum = remote_sync_list[object_id]
                try:
                    local_checksum = local_sync_list[object_id]
                except Exception as e:
                    # If we do not have this object set it to None to
                    # get it updated.
                    local_checksum = None
                # Get checksum from sync cache.
                if local_checksum is None:
                    try:
                        local_checksum = self.sync_cache[object_id]['SYNC_CHECKSUM']
                    except:
                        local_checksum = None

                # Check if we need to update this object.
                if remote_checksum == local_checksum:
                    continue
                # Add object to be synced.
                object_type = oid.get_object_type(object_id)
                try:
                    sync_data = _sync_objects[object_type]
                except:
                    sync_data = {}
                sync_data[object_id] = {}
                sync_data[object_id]['local_checksum'] = local_checksum
                sync_data[object_id]['remote_checksum'] = remote_checksum
                _sync_objects[object_type] = sync_data
                object_count += 1

            # Get objects in receive order. We sync objects that can have
            # tokens assigned at the end because chances are higher that
            # they change while syncing.
            # Sync objects.
            object_counter = 0
            for object_type in config.object_sync_order:
                try:
                    object_list = _sync_objects[object_type]
                except:
                    continue
                for object_id in sorted(object_list):
                    # Count.
                    object_counter += 1
                    # Increase progress.
                    self.update_sync_progress(realm=realm,
                                            site=site,
                                            sync_type="objects")

                    # Check if object is already in sync cache.
                    try:
                        object_config = self.sync_cache[object_id]
                    except:
                        # If its not in our sync cache check it already exist
                        # on our site.
                        try:
                            object_config = backend.read_config(object_id)
                        except Exception as e:
                            object_config = None

                    # Build attribute checksums. They are used by the remote
                    # site to transfer only changed parameters of the object
                    # config.
                    object_checksums = {}
                    if object_config:
                        for attribute in object_config:
                            value = str(object_config[attribute])
                            checksum = stuff.gen_md5(value)
                            object_checksums[attribute] = checksum
                        msg = ("Syncing remote object (%s/%s): %s"
                            % (object_counter, object_count, object_id))
                    else:
                        msg = ("Receiving remote object (%s/%s): %s"
                            % (object_counter, object_count, object_id))
                    if config.debug_level() > 2:
                        self.logger.debug(msg)
                    else:
                        print_processed_msg = False
                        x_count = object_counter / 10
                        if not x_count % 1:
                            print_processed_msg = True
                        if object_counter == object_count:
                            print_processed_msg = True
                        if print_processed_msg:
                            msg = "Received %s/%s objects..." % (object_counter, object_count)
                            self.logger.info(msg)

                    command_args = {}
                    command_args['realm'] = realm
                    command_args['site'] = site
                    command_args['object_id'] = object_id
                    command_args['object_checksums'] = object_checksums
                    command_args.update(sync_params)

                    status, \
                    status_code, \
                    reply, \
                    binary_data = self.connection.send("get_object", command_args)

                    if not status:
                        msg = ("Error receiving object %s: %s"
                                % (object_id, reply))
                        self.logger.warning(msg)
                        # Make sure we try again.
                        remote_sync_list_checksum = None
                        continue

                    if reply == "SYNC_UNKNOWN_OBJECT":
                        msg = ("Object deleted on remote site while syncing: %s"
                                % object_id)
                        self.logger.warning(msg)
                    else:
                        new_checksum = reply['checksum']
                        new_object_config = reply['object_config']
                        if not ignore_changed_objects:
                            # Make sure object has not changed while synching.
                            old_checksum = object_list[object_id]['remote_checksum']
                            if new_checksum != old_checksum:
                                msg = ("Object changed while syncing: %s" % object_id)
                                self.logger.warning(msg)
                                self.sync_cache.delete(object_id)
                                # Make sure we try again.
                                remote_sync_list_checksum = None
                                changed_object = True
                                continue
                        # Check for object checksum.
                        if "CHECKSUM" not in new_object_config:
                            msg = "Object misses checksum: %s" % object_id
                            self.logger.warning(msg)
                            continue
                        # Merge remote/local object config.
                        for attribute in new_object_config:
                            value = new_object_config[attribute]
                            if value == "USE_LOCAL":
                                local_value = object_config[attribute]
                                new_object_config[attribute] = local_value

                        # Update object in sync dict.
                        self.sync_cache[object_id] = new_object_config
                        received_objects += 1
                        #self.logger.debug("Received object: %s" % object_id)

            if received_objects > 0:
                self.logger.info("Received %s objects from peer."
                                % received_objects)
                received_objects = 0

            # We only need to do a re-check with the master node if there was an
            # error receiving an object (remote_sync_list_checksum=None) or if the re-
            # check is mandatory (default).
            do_recheck = True
            if ignore_changed_objects:
                if remote_sync_list_checksum:
                    do_recheck = False
            if not changed_object:
                do_recheck = False

            if not do_recheck:
                if ignore_changed_objects:
                    msg = ("Not re-checking sync status with master node "
                            "(--ignore-changed-objects).")
                    self.logger.info(msg)
                sync_success = True
                break

            # Do re-check with master node.
            old_remote_sync_list_checksum = remote_sync_list_checksum
            try:
                self.logger.info("Rechecking sync state with peer.")
                sync_list_response = self.get_remote_sync_list(realm=realm,
                                                            site=site,
                                                            sync_params=sync_params)
            except PermissionDenied:
                # Pass on exception to calling method.
                raise
            except SyncDisabled:
                # Pass on exception to calling method.
                raise
            except Exception as e:
                self.logger.critical("Error getting remote sync list: %s" % e)
                config.raise_exception()
                return False
            # Get sync parameters from response.
            sync_params = sync_list_response['sync_params']
            skip_list = sync_params['skip_list']
            skip_admin = sync_params['skip_admin']
            skip_users = sync_params['skip_users']
            sync_object_types = sync_params['object_types']
            remote_sync_list_checksum = sync_list_response['sync_list_checksum']
            remote_sync_list = sync_list_response['sync_list']
            # Set sync parameters to cache.
            self.sync_cache.sync_parameters = sync_params

            if old_remote_sync_list_checksum == remote_sync_list_checksum:
                self.logger.info("Local sync cache up-to-date with peer: %s"
                                % (remote_sync_list_checksum))
                sync_success = True
                break

        # If we got a good sync state merge changes from sync cache.
        if sync_success:
            # Write sync lists to cache.
            self.sync_cache.local_sync_list = local_sync_list
            self.sync_cache.remote_sync_list = remote_sync_list
            # Merge sync cache.
            self.merge_sync_cache(realm, site,
                            sync_older_objects=sync_older_objects,
                            skip_object_deletion=skip_object_deletion)
        else:
            if not skip_object_deletion:
                self.remove_deleted_objects(realm, site, local_sync_list,
                                            remote_sync_list, sync_params)
        # Count objects.
        synced_objects_count = len(self.synced_objects) + len(self.removed_objects)
        failed_objects_count = len(self.failed_objects)

        if sync_success:
            new_local_checksum = local_sync_list_checksum
            if synced_objects_count > 0 or failed_objects_count > 0:
                if failed_objects_count == 0:
                    # On success we can clear our sync cache.
                    self.sync_cache.clear()
                    msg = ("Sync finished successful. Synchronized %s objects."
                            % synced_objects_count)
                    self.logger.info(msg)
                else:
                    msg = ("Sync finished with errors. Synchronized %s objects, "
                            "%s failed." % (synced_objects_count,
                                            failed_objects_count))
                    self.logger.critical(msg)
        else:
            if local_sync_list_checksum == remote_sync_list_checksum:
                msg = ("Remote config checksum matches local. "
                        "No sync needed: %s" % local_sync_list_checksum)
                self.logger.info(msg)
                new_local_checksum = local_sync_list_checksum
                sync_success = True
                exit_status = None
            else:
                msg = ("Unable to get consistent sync state with peer after %s "
                        "tries." % try_count)
                self.logger.warning(msg)
                new_local_checksum = local_sync_list_checksum
                exit_status = False

        # Update our sync status on peer node.
        try:
            self.send_sync_list_checksum(realm=realm,
                                        site=site,
                                        sync_params=sync_params,
                                        checksum=new_local_checksum)
        except PermissionDenied:
            # Pass on exception to calling method.
            raise
        except SyncDisabled:
            # Pass on exception to calling method.
            raise
        except Exception as e:
            self.logger.critical("Error sending sync list to peer: %s" % e)
            config.raise_exception()
            return False

        return exit_status

    def merge_sync_cache(self, realm, site,
        sync_older_objects=False, skip_object_deletion=True):
        """ Merge sync cache. """
        add_list = {}
        add_order = list(config.object_add_order)
        own_realm, own_site = get_own_realm_site()
        # On hosts realm/sites are synced by HostDaemon().sync_sites().
        if config.host_data['type'] == "host":
            add_order.remove("realm")
            add_order.remove("site")

        # Get sync lists from cache.
        local_sync_list = self.sync_cache.local_sync_list
        remote_sync_list = self.sync_cache.remote_sync_list
        # Missing remote sync list means incomplete sync cache.
        if not remote_sync_list:
            return

        # Get sync object types.
        sync_params = self.sync_cache.sync_parameters
        valid_object_types = sync_params['valid_object_types']

        # Add empty list to add_list dict for each object type.
        for i in add_order: add_list[i] = []

        self.logger.info("Started merging of sync cache...")

        # We have to remove deleted objects before syncing new/changed objects
        # because we need e.g. the token <> group relationship to update e.g.
        # memberUid attributes of groups.
        if not skip_object_deletion:
            self.remove_deleted_objects(realm, site, local_sync_list,
                                        remote_sync_list, sync_params)

        # Build list with objects to add or update grouped by object type.
        object_count = 0
        for x in remote_sync_list:
            remote_checksum = remote_sync_list[x]
            # Try to get local checksum.
            try:
                local_checksum = local_sync_list[x]
            except:
                local_checksum = None

            # Increase progress.
            self.update_sync_progress(realm=realm,
                                    site=site,
                                    sync_type="objects")

            # If checksums are the same no need to update the object.
            if remote_checksum == local_checksum:
                continue

            # Get object infos.
            object_id = oid.get(object_id=x)
            object_type = object_id.object_type

            # On hosts we should never get a realm or site object here. They are
            # synced by HostDaemon().sync_sites().
            if config.host_data['type'] == "host":
                if object_type == "realm" or object_type == "site":
                    msg = ("Peer sent us forbidden %s object: %s"
                            % (object_type, object_id))
                    self.logger.critical(msg)
                    continue

            # Add object to add list.
            add_list[object_type].append(object_id)
            object_count += 1

        def log_progress(x_oid, child, object_counter, object_count):
            if config.debug_level() > 2:
                if child.exitcode == 0:
                    msg = ("Added object (%s/%s): %s"
                            % (object_counter, object_count, x_oid))
                else:
                    msg = ("Updated object (%s/%s): %s"
                            % (object_counter, object_count, x_oid))
                self.logger.debug(msg)
            else:
                print_processed_msg = False
                x_count = object_counter / 10
                if not x_count % 1:
                    print_processed_msg = True
                if object_counter == object_count:
                    print_processed_msg = True
                if print_processed_msg:
                    msg = "Processed %s/%s objects..." % (object_counter, object_count)
                    self.logger.info(msg)

        # Merge all updates.
        object_counter = 0
        prev_object_type = None
        update_realm_ca_data = False
        #procs = int(os.cpu_count() / 2)
        procs = os.cpu_count()
        for object_type in add_order:
            if prev_object_type is None:
                prev_object_type = object_type
            # Get object list.
            try:
                object_list = sorted(add_list[object_type])
            except KeyError:
                object_list = []
            # Skip object types not in list.
            if not object_list:
                continue
            if not object_type in valid_object_types:
                msg = ("Got object type to sync that is not known for this host "
                        "type. This is most likley a bug: %s" % object_type)
                self.logger.critical(msg)
                continue
            # Add objects to progress calculation.
            self.update_sync_progress(realm=realm,
                                    site=site,
                                    sync_type="objects",
                                    object_count=len(object_list))
            x_add_order = {}
            for x_oid in object_list:
                x_path_len = len(x_oid.path.split("/"))
                x_add_order[x_oid] = {}
                x_add_order[x_oid]['path_len'] = x_path_len

            x_sort = lambda x: x_add_order[x]['path_len']
            x_add_order_sorted = sorted(x_add_order, key=x_sort)
            for object_id in x_add_order_sorted:
                # Increase progress.
                self.update_sync_progress(realm=realm,
                                        site=site,
                                        sync_type="objects")
                # Get object config from sync cache.
                object_config = self.sync_cache[object_id]

                if not object_config:
                    continue

                while True:
                    for x_oid in list(self.mass_add_procs):
                        child = self.mass_add_procs[x_oid]
                        if child.is_alive():
                            continue
                        child.join()
                        self.mass_add_procs.pop(x_oid)
                        if child.exitcode == 0 or child.exitcode == 100:
                            object_counter += 1
                            log_progress(x_oid, child, object_counter, object_count)
                        else:
                            msg = "Failed to process object: %s" % x_oid
                            self.logger.warning(msg)
                    time.sleep(0.01)
                    if prev_object_type != object_type:
                        if len(self.mass_add_procs) > 0:
                            continue
                        prev_object_type = object_type
                    if len(self.mass_add_procs) < procs:
                        break

                proc_child = multiprocessing.start_process(name="process_object",
                                        target=self.process_object,
                                        target_args=(object_id,
                                                    object_config,
                                                    realm,
                                                    site,
                                                    own_realm,
                                                    own_site,
                                                    sync_older_objects,
                                                    local_sync_list,),
                                        start=False,
                                        daemon=True)
                proc_child.start()
                self.mass_add_procs[object_id] = proc_child

                if object_id.object_type == "ca":
                    update_realm_ca_data = True


        while True:
            for x_oid in list(self.mass_add_procs):
                child = self.mass_add_procs[x_oid]
                if child.is_alive():
                    continue
                child.join()
                self.mass_add_procs.pop(x_oid)
                if child.exitcode == 0 or child.exitcode == 100:
                    object_counter += 1
                    log_progress(x_oid, child, object_counter, object_count)
                else:
                    msg = "Failed to process object: %s" % x_oid
                    self.logger.warning(msg)
            time.sleep(0.01)
            if len(self.mass_add_procs) > 0:
                continue
            break

        # Update realm CA data if the master node  received a changed CA.
        if update_realm_ca_data:
            if config.realm_master_node:
                msg = "Updating realm CA data..."
                self.logger.info(msg)
                realm = backend.get_object(uuid=config.realm_uuid)
                realm.update_ca_data(verify_acls=False)

    def process_object(self, object_id, object_config, realm, site,
        own_realm, own_site, sync_older_objects, local_sync_list):
        proctitle = setproctitle.getproctitle()
        proctitle = ("%s: Sync object %s:" % (proctitle, object_id))
        setproctitle.setproctitle(proctitle)

        multiprocessing.atfork()
        def exit_child(exit_code):
            multiprocessing.cleanup()
            sys.exit(exit_code)
        # Make sure parent object exists on our site.
        if object_id.object_type in config.tree_object_types:
            try:
                parent_object_uuid = object_config.pop('SYNC_PARENT_OBJECT_UUID')
            except Exception as e:
                msg = "Failed to get parent object UUID: %s: %s" % (object_id, e)
                self.logger.critical(msg)
                exit_child(1)
            parent_object = backend.get_object(uuid=parent_object_uuid)
            if not parent_object:
                msg = ("Unable to sync object with missing parent object: "
                        "%s: %s" % (object_id, parent_object_uuid))
                self.logger.warning(msg)
                exit_child(1)

        # Load instance.
        try:
            new_object = backend.get_instance_from_oid(object_id,
                                                    object_config)
        except Exception as e:
            self.failed_objects.append(object_id)
            msg = "Failed to load new object: %s: %s" % (object_id, e)
            self.logger.critical(msg)
            exit_child(1)

        if object_id.object_type == "user":
            user_site = object_id.site
            if user_site != own_site:
                # Prevent sync of users that exist on our site.
                user_name = object_id.name
                local_oid = oid.get(object_type="user",
                                    realm=own_realm,
                                    site=own_site,
                                    name=user_name)
                if not new_object.template_object:
                    if backend.object_exists(local_oid):
                        self.blacklisted_users.append(user_name)
                        msg = ("User already exists on our site: %s"
                                % object_id)
                        self.logger.warning(msg)
                        exit_child(1)
                # Prevent sync of user with duplicate uidNumber.
                found_duplicate = False
                user_uidnumber = new_object.get_attribute("uidNumber")
                for x_uidnumber in user_uidnumber:
                    result = backend.search(object_type="user",
                                            attribute="ldif:uidNumber",
                                            value=x_uidnumber,
                                            return_type="oid")
                    if not result:
                        continue
                    x_oid = result[0]
                    if x_oid == new_object.oid:
                        continue
                    msg = ("Cannot sync user with duplicate uidNumber: %s: %s <> %s"
                            % (x_uidnumber, new_object, x_oid))
                    found_duplicate = True
                    break
                if found_duplicate:
                    self.logger.warning(msg)
                    exit_child(1)

        if object_id.object_type == "group":
            group_site = object_id.site
            if group_site != own_site:
                # Prevent sync of groups that exist on our site.
                group_name = object_id.name
                local_oid = oid.get(object_type="group",
                                    realm=own_realm,
                                    site=own_site,
                                    name=group_name)
                if not new_object.template_object:
                    if backend.object_exists(local_oid):
                        msg = ("Group already exists on our site: %s"
                                % object_id)
                        self.logger.warning(msg)
                        exit_child(1)
                # Prevent sync of group with duplicate gidNumber.
                found_duplicate = False
                group_gidnumber = new_object.get_attribute("gidNumber")
                for x_gidnumber in group_gidnumber:
                    result = backend.search(object_type="group",
                                            attribute="ldif:gidNumber",
                                            value=x_gidnumber,
                                            return_type="oid")
                    if not result:
                        continue
                    x_oid = result[0]
                    if x_oid == new_object.oid:
                        continue
                    msg = ("Cannot sync group with duplicate gidNumber: %s: %s <> %s"
                            % (x_gidnumber, new_object, x_oid))
                    found_duplicate = True
                    break
                if found_duplicate:
                    self.logger.warning(msg)
                    exit_child(1)

        if object_id.object_type == "token":
            # Skip blacklisted user tokens.
            user_name = object_id.rel_path.split("/")[0]
            if user_name in self.blacklisted_users:
                exit_child(200)
            # Make sure we update LDIF/nsscache.
            x_groups = new_object.get_groups(return_type="full_oid")
            for full_oid in x_groups:
                full_oid = oid.get(full_oid)
                nsscache.update_object(full_oid, "update")
            x_roles = new_object.get_roles(return_type="full_oid", recursive=True)
            for full_oid in x_roles:
                full_oid = oid.get(full_oid)
                nsscache.update_object(full_oid, "update")

        # Make sure the object is valid.
        site_oid = oid.get(object_type="site", realm=realm, name=site)
        try:
            validate_received_object(site_oid, new_object)
        except Exception as e:
            self.failed_objects.append(object_id)
            msg = "Received invalid object: %s" % e
            self.logger.critical(msg)
            exit_child(1)

        # We must prevent syncing of duplicate UUIDs between sites.
        # Within a normal sync the UUID may already exist at the same
        # site (e.g. a object rename) but should never exist on a
        # different site because this may be used to do some privilege
        # escalation (e.g. add a token with the same UUID as the realm
        # admin token).
        current_object = backend.get_object(uuid=new_object.uuid)
        # Check if the object is from an other site.
        if current_object:
            if current_object.site != new_object.site:
                msg = ("Ignoring duplicate UUID: %s: %s <> %s"
                        % (new_object.uuid, current_object.oid, object_id))
                self.logger.warning(msg)
                exit_child(1)

        # Skip new object that is older than the current one.
        if current_object is not None:
            if config.host_data['type'] == "node":
                # Allow older object if its the own node. This is required
                # because clusterd en-/disables the own node object.
                if not sync_older_objects:
                    if realm == own_realm and site == own_site:
                        if current_object.uuid != config.uuid:
                            if current_object.last_modified > new_object.last_modified:
                                msg = "Ignoring older object from peer: %s" % object_id
                                self.logger.warning(msg)
                                exit_child(1)

        # Removed old object with different OID (e.g. object was
        # moved).
        if current_object is not None:
            if new_object.oid.full_oid != current_object.oid.full_oid:
                try:
                    local_sync_list.pop(current_object.oid.full_oid)
                except KeyError:
                    pass
                backend.delete_object(current_object.oid)

        # Load current object UUID.
        try:
            current_uuid = backend.get_uuid(object_id)
        except:
            current_uuid = None
        # Removed old object with different UUID (e.g. object was
        # re-created).
        if current_uuid is not None:
            if new_object.uuid != current_uuid:
                try:
                    local_sync_list.pop(object_id.full_oid)
                except KeyError:
                    pass
                try:
                    backend.delete_object(object_id)
                except UnknownObject:
                    pass

        # Write object to backend.
        cluster = False
        if self.host_type == "node":
            if realm == own_realm:
                if site == own_site:
                    if config.master_node:
                        cluster = True
        try:
            backend.write_config(object_id,
                            instance=new_object,
                            full_data_update=True,
                            full_index_update=True,
                            full_ldif_update=True,
                            full_acl_update=True,
                            cluster=cluster)
            self.synced_objects.append(object_id.read_oid)
        except Exception as e:
            self.failed_objects.append(object_id)
            msg = ("Error writing object %s to backend: %s"
                    % (object_id, e))
            self.logger.critical(msg)
            config.raise_exception()

        # Update signers cache.
        if new_object.type == "user":
            if new_object.public_key:
                try:
                    public_key = sign_key_cache.get_cache(object_id)
                except Exception as e:
                    msg = "Unable to read signer cache: %s: %s" % (object_id, e)
                    self.logger.critical(msg)
                    public_key = None
                if new_object.public_key != public_key:
                    try:
                        sign_key_cache.add_cache(object_id, new_object.public_key)
                    except Exception as e:
                        msg = "Unable to add signer cache: %s: %s" % (object_id, e)
                        self.logger.critical(msg)
            else:
                try:
                    public_key = sign_key_cache.get_cache(object_id)
                except Exception as e:
                    msg = "Unable to read signer cache: %s: %s" % (object_id, e)
                    self.logger.critical(msg)
                    public_key = None
                if public_key:
                    try:
                        sign_key_cache.del_cache(object_id)
                    except Exception as e:
                        msg = "Unable to add signer cache: %s: %s" % (object_id, e)
                        self.logger.critical(msg)
        if current_object is None:
            exit_child(0)
        else:
            exit_child(100)


    def remove_deleted_objects(self, realm, site, local_sync_list,
        remote_sync_list, sync_params):
        """ Remove deleted objects. """
        self.logger.info("Checking for deleted objects...")
        del_list = {}
        del_count = 0
        del_order = list(config.object_add_order)
        own_realm, own_site = get_own_realm_site()
        # Realm/sites are synced by HostDaemon().sync_sites().
        del_order.remove("realm")
        del_order.remove("site")
        del_order = list(del_order)
        del_order.reverse()
        valid_object_types = sync_params['valid_object_types']
        # Add empty list to del_list dict for each object type.
        for i in del_order: del_list[i] = []
        # Build list with objects to remove grouped by object type.
        for x in local_sync_list:
            # Check if the objects is present in remote sync list.
            try:
                remote_sync_list[x]
            except:
                x_oid = oid.get(object_id=x)
                # Add remote missing objects to del list.
                object_type = x_oid.object_type
                del_list[object_type].append(x_oid)
                del_count += 1

        # Remove deleted objects.
        del_counter = 0
        for object_type in del_order:
            # Get object list.
            try:
                object_list = del_list[object_type]
            except:
                object_list = []
            # Skip object types not in list.
            if not object_list:
                continue
            if not object_type in valid_object_types:
                msg = ("Got object type to sync that is not known for this host "
                        "type. This is most likley a bug: %s" % object_type)
                self.logger.critical(msg)
                continue
            # Add objects to progress calculation.
            self.update_sync_progress(realm=realm,
                                    site=site,
                                    sync_type="objects",
                                    object_count=len(object_list))

            x_del_order = {}
            for x_oid in object_list:
                x_path_len = len(x_oid.path.split("/"))
                x_del_order[x_oid] = {}
                x_del_order[x_oid]['path_len'] = x_path_len

            x_sort = lambda x: x_del_order[x]['path_len']
            x_del_order_sorted = sorted(x_del_order, key=x_sort, reverse=True)
            for object_id in x_del_order_sorted:
                del_counter += 1
                # Increase progress.
                self.update_sync_progress(realm=realm,
                                        site=site,
                                        sync_type="objects")
                # Skip updated objects (e.g. user moved from one
                # unit to another).
                if not backend.object_exists(object_id):
                    continue
                # Update signers cache.
                if object_type == "user":
                    sign_key_cache.del_cache(object_id)
                # Make sure we update LDIF/nsscache.
                if object_type == "token":
                    x_object = backend.get_object(object_id)
                    if not x_object:
                        continue
                    x_groups = x_object.get_groups(return_type="full_oid")
                    for full_oid in x_groups:
                        full_oid = oid.get(full_oid)
                        nsscache.update_object(full_oid, "update")
                    x_roles = x_object.get_roles(return_type="full_oid", recursive=True)
                    for full_oid in x_roles:
                        full_oid = oid.get(full_oid)
                        nsscache.update_object(full_oid, "update")
                # Remove object.
                msg = ("Removing object (%s/%s): %s"
                    % (del_counter, del_count, object_id))
                self.logger.debug(msg)
                cluster = False
                if self.host_type == "node":
                    if realm == own_realm:
                        if site == own_site:
                            if config.master_node:
                                cluster = True
                try:
                    backend.delete_object(object_id, cluster=cluster)
                except Exception as e:
                    msg = "Failed to delete object: %s: %s" % (object_id, e)
                    self.logger.critical(msg)
                    self.removed_objects.append(object_id.read_oid)

    def get_token_data(self, data_type, local_objects,
        token_oid=None, session_uuid=None, offline=False):
        """ Try to get token data from peer. """
        try_count = 0
        max_tries = 3
        objects = {
                    'new_objects'       : {},
                    'outdated_objects'  : {},
                }

        if data_type == "otp":
            log_name = "used OTP"
        if data_type == "counter":
            log_name = "token counter"

        self.logger.debug("Requesting list with %ss from peer: %s"
                        % (log_name, self.connection.peer.name))

        if offline:
            command = "sync_offline_token_data"
        else:
            command = "sync_token_data"
        command_args = {
                        'token_oid'         : token_oid,
                        'data_type'         : data_type,
                        'session_uuid'      : session_uuid,
                        'remote_objects'    : local_objects,
                    }
        while try_count < max_tries:
            status, \
            status_code, \
            reply, \
            binary_data = self.connection.send(command, command_args)
            if not status:
                if status_code == status_codes.UNKNOWN_OBJECT:
                    raise UnknownObject(reply)
                try_count += 1
                msg = ("Error receiving list from peer: %s"
                        % reply)
                self.logger.error(msg)
                msg = ("Retrying (%s/%s)" % (try_count, max_tries))
                self.logger.error(msg)
                time.sleep(1)
                continue

            for t in reply:
                for x in reply[t]:
                    x_config = reply[t][x]
                    x_oid = oid.get(object_id=x)
                    if t not in objects:
                        objects[t] = {}
                    objects[t][x_oid] = x_config

            msg = ("Received %s objects from peer."
                % len(objects['new_objects']))
            self.logger.debug(msg)
            break

        return objects

    def _sync_token_data(self, data_type="otp", offline=False):
        # Acquire sync lock.
        own_realm, own_site = get_own_realm_site()
        lock_id = "sync_%s:%s/%s" % (data_type, own_realm, own_site)
        sync_lock = locking.acquire_lock(lock_type=LOCK_TYPE, lock_id=lock_id)
        if offline:
            try:
                result = self.__sync_offline_token_data(data_type=data_type)
            finally:
                sync_lock.release_lock()
        else:
            try:
                result = self.__sync_token_data(data_type=data_type)
            finally:
                sync_lock.release_lock()
        return result

    def __sync_offline_token_data(self, data_type="otp"):
        """ Sync token data (e.g. used OTPs) with peer. """
        from otpme.lib.offline_token import OfflineToken
        exit_status = True
        sync_counter = False
        sync_otps = False

        if data_type == "otp":
            log_name = "used OTP"
            sync_otps = True

        if data_type == "counter":
            log_name = "token counter"
            sync_counter = True

        self.logger.info("Starting sync of offline %ss..." % log_name)

        try:
            user_uuids = []
            for uuid in os.listdir(config.offline_dir):
                if not stuff.is_uuid(uuid):
                    continue
                user_uuids.append(uuid)
        except:
            self.logger.debug("No offline tokens found.")
            return True

        for uuid in user_uuids:
            user = backend.get_object(uuid=uuid)
            if user.realm != self.connection.realm:
                continue
            if user.site != self.connection.site:
                continue
            # Set user we want to read offline tokens for.
            try:
                offline_token = OfflineToken()
                offline_token.set_user(uuid=uuid)
            except UnknownUser:
                msg = (_("Ignoring offline token of unknown user: %s") % uuid)
                self.logger.info(msg)
                continue
            except Exception as e:
                self.logger.critical("Error loading offline tokens: %s" % e)
                config.raise_exception()
                continue
            # Acquire offline token lock.
            offline_token.lock()
            # Get offline tokens.
            try:
                offline_token.load()
                user_tokens = offline_token.get()
            except Exception as e:
                msg = ("Error getting offline tokens: %s: %s"
                    % (offline_token.username, e))
                self.logger.critical(msg)
                # Release offline token lock.
                offline_token.unlock()
                config.raise_exception()
                continue

            # Skip user without offline tokens.
            if not user_tokens:
                offline_token.unlock()
                continue

            # Try to get server session UUID.
            try:
                session_uuid = offline_token.session_uuid
                if not session_uuid:
                    msg = (_("Unable to get server session UUID."))
                    raise OTPmeException(msg)
            except Exception as e:
                msg = (_("Error getting offline session UUID: %s: %s")
                        % (offline_token.username, e))
                self.logger.critical(msg)
                # Release offline token lock.
                offline_token.unlock()
                continue

            for x in user_tokens:
                token = user_tokens[x]
                if token.pass_type != "otp":
                    continue
                if sync_otps:
                    if not token.sync_offline_otps:
                        continue
                if sync_counter:
                    if not token.sync_offline_token_counter:
                        continue

                if sync_otps:
                    get_method = offline_token._get_used_otps

                if sync_counter:
                    get_method = offline_token._get_token_counter

                # Get list with local objects.
                local_objects = {}
                for x_oid, x_object_config in get_method(token.oid):
                    if x_oid.realm != self.connection.realm:
                        continue
                    if x_oid.site != self.connection.site:
                        continue
                    local_objects[x_oid.read_oid] = dict(x_object_config)

                if not local_objects:
                    continue

                # Try to get list with remote objects that we are missing.
                try:
                    remote_objects = self.get_token_data(data_type=data_type,
                                            token_oid=token.oid.read_oid,
                                            session_uuid=session_uuid,
                                            local_objects=local_objects,
                                            offline=True)
                except UnknownObject:
                    for x_oid, x_object_config in get_method(token.oid):
                        if offline_token.delete_object(x_oid):
                            msg = "Removing outdated object: %s" % x_oid
                            self.logger.info(msg)
                    continue

                # Add remote objects.
                for x_oid in remote_objects['new_objects']:
                    x_config = remote_objects['new_objects'][x_oid]
                    if offline_token.write_config(object_id=x_oid,
                                            object_config=x_config,
                                            encrypt=False):
                        self.synced_objects.append(x_oid.read_oid)

                # Remove outdated objects.
                for x_oid in remote_objects['outdated_objects']:
                    if offline_token.delete_object(x_oid):
                        msg = ("Removed %s: %s" % (data_type, x_oid))
                        self.logger.debug(msg)
                        self.removed_objects.append(x_oid.read_oid)

                new_object_count = len(self.synced_objects)
                self.logger.debug("Added %s new %ss: %s"
                                % (new_object_count,
                                log_name,
                                token.rel_path))

            # Release offline token lock.
            offline_token.unlock()

        all_new_object_count = len(self.synced_objects)
        if all_new_object_count > 0:
            self.logger.info("Successfully synchronized %s offline %ss."
                            % (all_new_object_count, log_name))
        else:
            self.logger.info("Local token data up-to-date.")

        return exit_status

    def __sync_token_data(self, data_type="otp"):
        """ Sync token data (e.g. used OTPs) with peer. """
        sync_otps = False
        exit_status = True
        sync_counter = False

        if data_type == "otp":
            log_name = "used OTP"
            sync_otps = True

        if data_type == "counter":
            log_name = "token counter"
            sync_counter = True

        self.logger.info("Starting sync of %ss..." % log_name)

        if sync_otps:
            result = backend.search(object_type="used_otp",
                                    attribute="uuid",
                                    value="*",
                                    return_type="instance")
        if sync_counter:
            result = backend.search(object_type="token_counter",
                                    attribute="uuid",
                                    value="*",
                                    return_type="instance")

        # Get list with local objects.
        local_objects = {}
        for x_object in result:
            local_objects[x_object.oid.read_oid] = x_object.object_config.copy()

        # Try to get list with remote objects that we are missing.
        remote_objects = self.get_token_data(data_type=data_type,
                                            local_objects=local_objects)
        # Add remote objects.
        for x_oid in remote_objects['new_objects']:
            x_config = remote_objects['new_objects'][x_oid]
            x_object = backend.get_object(uuid=x_oid.token_uuid)
            if not x_object:
                continue
            if backend.write_config(object_id=x_oid,
                                    object_config=x_config,
                                    full_index_update=True,
                                    full_data_update=True,
                                    full_acl_update=True):
                self.synced_objects.append(x_oid.read_oid)

        # Remove outdated objects.
        for x_oid in remote_objects['outdated_objects']:
            if backend.delete_object(x_oid):
                msg = ("Removed %s: %s" % (data_type, x_oid))
                self.logger.debug(msg)
                self.removed_objects.append(x_oid.read_oid)
            continue

        new_object_count = len(self.synced_objects)
        self.logger.debug("Added %s new %ss:" % (new_object_count, log_name))

        all_new_object_count = len(self.synced_objects)
        if all_new_object_count > 0:
            self.logger.info("Successfully synchronized %s %ss."
                            % (all_new_object_count, log_name))
        else:
            self.logger.info("Local token data up-to-date.")

        return exit_status

    def sync_ssh_authorized_keys(self, **kwargs):
        # Acquire sync lock.
        lock_id = "sync_ssh_authorized_keys"
        sync_lock = locking.acquire_lock(lock_type=LOCK_TYPE, lock_id=lock_id)
        try:
            result = self._sync_ssh_authorized_keys(**kwargs)
        finally:
            sync_lock.release_lock()
        return result

    def _sync_ssh_authorized_keys(self):
        """ Try to get SSH authorized_keys from peer. """
        received_ssh_keys = {}
        exit_status = True
        try_count = 0
        max_tries = 3

        self.logger.info("Requesting authorized_keys from peer...")

        while try_count < max_tries:
            status, \
            status_code, \
            reply, \
            binary_data = self.connection.send("get_ssh_authorized_keys")
            if not status:
                try_count += 1
                msg = ("Error receiving SSH authorized_keys from peer: %s"
                        % reply)
                self.logger.error(msg)
                msg = ("Retrying (%s/%s)" % (try_count, max_tries))
                self.logger.error(msg)
                time.sleep(1)
                continue
            received_ssh_keys = reply
            break

        if not status:
            return False

        # Make sure we sync all objects we need to verify SSH keys assigned to
        # our host.
        for token_uuid in received_ssh_keys:
            # Check if we need to sync the token...
            token = backend.get_object(object_type="token",
                                        uuid=token_uuid)
            if not token:
                return
            # Token groups.
            token_groups = token.get_groups(return_type="uuid")
            for group_uuid in token_groups:
                group = backend.get_object(object_type="group",
                                            uuid=group_uuid)
                if not group:
                    return
            # User.
            user = backend.get_object(object_type="user",
                                    uuid=token.owner_uuid)
            if not user:
                return

            # Policies.
            for policy_uuid in user.policies:
                policy = backend.get_object(object_type="policy",
                                             uuid=policy_uuid)
                if not policy:
                    return

            for policy_uuid in token.policies:
                policy = backend.get_object(object_type="policy",
                                            uuid=policy_uuid)
                if not policy:
                    return

        # Save received keys to cache file.
        from otpme.lib import ssh
        # Get cached SSH keys.
        try:
            cached_ssh_keys = ssh.read_cached_ssh_keys()
        except Exception as e:
            msg = str(e)
            self.logger.critical(msg)
            exit_status = False
        # Write cache file only if SSH keys have changed.
        if exit_status:
            if received_ssh_keys != cached_ssh_keys:
                self.logger.debug("List of assigned SSH tokens changed.")
                ssh.write_cached_ssh_keys(received_ssh_keys)

        return exit_status

    def do_sync(self, sync_type="objects", sync_last_used=False,
        ignore_changed_objects=False, skip_object_deletion=False,
        sync_older_objects=False, max_tries=3, resync=False,
        offline=False, realm=config.realm, site=config.site):
        """ Sync objects with realm/site. """
        sync_status = False

        if sync_type == "objects":
            sync_status = self.sync_objects(realm=realm,
                                site=site,
                                resync=resync,
                                max_tries=max_tries,
                                sync_last_used=sync_last_used,
                                sync_older_objects=sync_older_objects,
                                skip_object_deletion=skip_object_deletion,
                                ignore_changed_objects=ignore_changed_objects)

        elif sync_type == "used_otps":
            if not self.connection:
                msg = "Unable to sync without connection to syncd."
                raise OTPmeException(msg)
            sync_status = self._sync_token_data(data_type="otp",
                                                offline=offline)
        elif sync_type == "token_counters":
            if not self.connection:
                msg = "Unable to sync without connection to syncd."
                raise OTPmeException(msg)
            sync_status = self._sync_token_data(data_type="counter",
                                                offline=offline)
        elif sync_type == "ssh_authorized_keys":
            if not self.connection:
                msg = "Unable to sync without connection to syncd."
                raise OTPmeException(msg)
            sync_status = self.sync_ssh_authorized_keys()
        else:
            msg = "Unknown sync type: %s" % sync_type
            raise OTPmeException(msg)

        ## Close sync connection.
        #if self.connection:
        #    self.connection.close()

        return sync_status
