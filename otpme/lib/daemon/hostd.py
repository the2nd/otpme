# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import sys
import time
import signal
import datetime
import setproctitle
from functools import wraps

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except:
    pass

from otpme.lib import log
from otpme.lib import oid
from otpme.lib import ssh
from otpme.lib import json
from otpme.lib import cache
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import locking
from otpme.lib import protocols
from otpme.lib import connections
from otpme.lib import multiprocessing
from otpme.lib.sync_cache import SyncCache
from otpme.lib.protocols import status_codes
from otpme.lib.audit import process_spooled_logs
from otpme.lib.daemon.otpme_daemon import OTPmeDaemon
from otpme.lib.protocols.client.sync1 import validate_received_object

from otpme.lib.exceptions import *

from otpme.lib import nsscache

LOCK_TYPE = "hostd.sync"

REGISTER_BEFORE = ['otpme.lib.daemon.controld']
REGISTER_AFTER = ['otpme.lib.offline_token']

def register():
    """ Register OTPme daemon. """
    config.register_otpme_daemon("hostd")
    locking.register_lock_type(LOCK_TYPE, module=__file__)

def handle_sync_child():
    """ Decorator to handle sync child processes. """
    def wrapper(f):
        @wraps(f)
        def wrapped(self, *f_args, **f_kwargs):
            try:
                sync_type = f_kwargs['sync_type']
            except:
                sync_type = "sync_sites"
            # Call given class method.
            try:
                result = f(self, *f_args, **f_kwargs)
            except Exception as e:
                log_msg = _("Unhandled exception in sync child: {function}: {sync_type}: {error}", log=True)[1]
                log_msg = log_msg.format(function=f.__name__, sync_type=sync_type, error=e)
                self.logger.critical(log_msg)
                result = False
                config.raise_exception()
            finally:
                self._send_local_daemon_msg("sync_done")
                multiprocessing.cleanup(keep_queues=True)
            if result is True:
                sys.exit(0)
            if result is False:
                sys.exit(0)
            return result
        return wrapped
    return wrapper

class HostDaemon(OTPmeDaemon):
    """ HostDaemon. """
    def __init__(self, *args, **kwargs):
        self.resolver_run_child = None
        self.remove_outdated_tokens_child = None
        self.clear_outdated_cache_objects_child = None
        super(HostDaemon, self).__init__(*args, **kwargs)

    def signal_handler(self, _signal, frame):
        """ Exit on signal. """
        if _signal != 15:
            return
        # Act only on our own PID.
        if os.getpid() != self.pid:
            return
        log_msg = _("Received SIGTERM.", log=True)[1]
        self.logger.info(log_msg)
        # Stop resolver runs.
        self.stop_resolvers()
        # Shutdown sync childs.
        self.shutdown_sync_childs()
        return super(HostDaemon, self).signal_handler(_signal, frame)

    def set_proctitle(self, proctitle=None, sync_type=None,
        resync=False, realm=None, site=None):
        """ Set daemon proctitle. """
        if sync_type:
            new_proctitle = f"{self.full_name} Syncing:"
            if realm and site:
                new_proctitle = f"{new_proctitle} /{realm}/{site}"
            if resync:
                new_proctitle = f"{new_proctitle} (resync {sync_type})"
            else:
                new_proctitle = f"{new_proctitle} ({sync_type})"
        elif proctitle:
            new_proctitle = f"{self.full_name} ({proctitle})"
        else:
            new_proctitle = self.full_name

        setproctitle.setproctitle(new_proctitle)

    def acquire_sync_lock(self, lock_id):
        """ Acquire sync lock. """
        try:
            sync_lock = locking.acquire_lock(lock_type=LOCK_TYPE, lock_id=lock_id)
        except Exception as e:
            sync_lock = None
            log_msg = _("Failed to acquire sync lock: {lock_id}: {error}", log=True)[1]
            log_msg = log_msg.format(lock_id=lock_id, error=e)
            self.logger.critical(log_msg)
        return sync_lock

    def get_site(self, realm, site):
        """ Get site instance. """
        result = backend.search(object_type="site",
                                attribute="name",
                                value=site,
                                realm=realm,
                                return_type="instance")
        if not result:
            msg = _("Unknown site: {realm}/{site}")
            msg = msg.format(realm=realm, site=site)
            raise OTPmeException(msg)

        return result[0]

    def get_sync_connection(self, realm=None, site=None,
        node=None, force_site_address=False):
        """ Get connection to syncd. """
        # Default connect realm/site is our own.
        connect_realm = config.realm
        connect_site = config.site

        if node:
            # Check if node exists.
            _node = backend.get_object(object_type="node",
                                        object_id=node)
            if not _node:
                msg = _("Unknown node: {node}")
                msg = msg.format(node=node)
                raise Exception(msg)
            connect_address = _node.fqdn
            connect_name = connect_address

        elif realm and site:
            connect_address = config.site_address
            if config.master_node or force_site_address:
                _site = self.get_site(realm, site)
                connect_address = _site.address
                connect_realm = realm
                connect_site = site
            connect_name = f"{connect_realm}/{connect_site}"
        else:
            raise Exception("Need realm/site or node.")

        # Set daemon port.
        daemon_port = config.default_ports['syncd']
        # Set socket URI.
        socket_uri = f"tcp://{connect_address}:{daemon_port}"

        log_msg = _("Trying to connect to syncd: {name}", log=True)[1]
        log_msg = log_msg.format(name=connect_name)
        self.logger.debug(log_msg)

        sync_conn = connections.get(daemon="syncd",
                                socket_uri=socket_uri,
                                realm=connect_realm,
                                site=connect_site,
                                timeout=0,
                                interactive=False)
        return sync_conn

    @property
    def host_type(self):
        try:
            host_type = config.host_data['type']
        except:
            return
        return host_type

    def reload_host_object(self):
        """ Reload own host object from backend. """
        host_type = self.host_type
        if host_type is None:
            log_msg = "Failed to load host object., log=True"[1]
            self.logger.critical(log_msg)
            return
        try:
            host = backend.get_object(object_type=host_type,
                                            uuid=config.uuid)
        except LockWaitTimeout:
            return
        except Exception as e:
            log_msg = _("Failed to reload host object: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            self.logger.critical(log_msg)
            return
        self.host = host

    def update_realm_data(self):
        """ Update realm data cache. """
        from otpme.lib import set_realm_site
        try:
            set_realm_site()
        except Exception as e:
            log_msg = _("Failed to set realm/site: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            self.logger.critical(log_msg)
            return False
        # Update realm data cache file.
        config.update_realm_data()

    def get_unsync_sites(self, timeout=None):
        """ Get nodes/sites that are not in sync with us. """
        # Only master nodes must send sync notifies.
        if not config.master_node:
            return

        # Our reply that will contain all nodes/sites that are not in sync.
        notify_sites = []

        # Get master site.
        master_site = backend.get_object(object_type="site",
                                        uuid=config.realm_master_uuid)
        # Get own site.
        own_site = backend.get_object(object_type="site",
                                    uuid=config.site_uuid)

        if own_site.uuid == master_site.uuid:
            # Realm master nodes must notify all non-master sites.
            peer_sites = backend.search(object_type="site",
                                        attribute="uuid",
                                        value="*",
                                        return_type="instance")
            # Realm master nodes must notify for any changed site.
            sync_sites = list(peer_sites)
        else:
            # Non-master sites must notify master site.
            peer_sites = [ master_site ]
            # Non-master sites must only notify about changes on their own site.
            sync_sites = [ own_site ]

        for x in peer_sites:
            # No need to notify own site.
            if x.uuid == own_site.uuid:
                continue
            # No need to notify disabled sites.
            if not x.enabled:
                continue
            # No need to notify sites we disabled sync with.
            if not x.sync_enabled:
                continue

            add_site = False
            for s in sync_sites:
                # No need to notify remote site for itself.
                if s.name == x.name:
                    continue

                # Get site entry from sync map.
                sync_list_checksum = backend.get_sync_map(realm=s.realm,
                                                        site=s.name,
                                                        peer_realm=x.realm,
                                                        peer_site=x.name,
                                                        timeout=timeout)
                # The sync list checksum may be the string "syncing" which
                # indicates an ongoing sync. In this case the peer is not in
                # sync but there was no object change on this node while it is
                # syncing and we do not want to resend a sync notify.
                if sync_list_checksum == config.SYNCING_STATUS_STRING:
                    log_msg = _("Site is currently syncing: {site}", log=True)[1]
                    log_msg = log_msg.format(site=x)
                    self.logger.debug(log_msg)
                if not sync_list_checksum:
                    add_site = True
                    break

            # Add site that is not in sync.
            if add_site:
                notify_sites.append(x)

        return notify_sites

    def sync_notify(self, realm, site, node=None):
        """ Send a sync notification to the given realm/site. """
        from otpme.lib.protocols.server.sync1 import add_sync_list_checksum
        if node:
            last_notify_id = f"node:{node}"
        else:
            last_notify_id = f"site:{realm}/{site}"

        try:
            last_sync_notify = self.last_notify[last_notify_id]
        except:
            last_sync_notify = 0

        notify_age = (int(time.time()) - int(last_sync_notify))

        # Make sure we honor sync notify limit.
        if notify_age < self.notify_limit:
            last_try = datetime.datetime.fromtimestamp(last_sync_notify)
            last_try = last_try.strftime('%H:%M:%S')
            log_msg = _("Not sending sync notification: {notify_id}: Last notify sent: {last_try}", log=True)[1]
            log_msg = log_msg.format(notify_id=last_notify_id, last_try=last_try)
            self.logger.debug(log_msg)
            return

        log_msg = _("Sending sync notification: {notify_id}", log=True)[1]
        log_msg = log_msg.format(notify_id=last_notify_id)
        self.logger.info(log_msg)
        # Get sync connection.
        try:
            sync_conn = self.get_sync_connection(realm=realm,
                                                site=site,
                                                node=node)
        except Exception as e:
            if node:
                sync_dst = node
            else:
                sync_dst = f"{realm}/{site}"
            log_msg = _("Error sending sync notification to {dst}: {error}", log=True)[1]
            log_msg = log_msg.format(dst=sync_dst, error=e)
            self.logger.warning(log_msg)
            return False

        # Get sync parameters.
        this_host = backend.get_object(uuid=config.uuid)
        sync_params = this_host.get_sync_parameters(realm, site, sync_conn.peer.uuid)

        status, \
        status_code, \
        reply, \
        binary_data = sync_conn.send("start_sync", command_args=sync_params)

        # Handle disabled sites.
        if status_code == status_codes.SYNC_DISABLED:
            log_msg = _("Cannot send sync notification to site that disabled sync with us: {realm}/{site}", log=True)[1]
            log_msg = log_msg.format(realm=realm, site=site)
            self.logger.warning(log_msg)
            return False

        if status_code != status_codes.OK:
            log_msg = _("Failed to send sync notification to site: {realm}/{site}: {reply}", log=True)[1]
            log_msg = log_msg.format(realm=realm, site=site, reply=reply)
            self.logger.warning(log_msg)
            return False

        # Update snyc status for each site the peer is syncing.
        sync_params = reply
        for x in sync_params:
            x_sync_time = x['time']
            x_sync_realm = x['realm']
            x_sync_site = x['site']
            x_skip_list = x['skip_list']
            x_skip_admin = x['skip_admin']
            x_object_types = x['object_types']
            try:
                reply = add_sync_list_checksum(realm=x_sync_realm,
                                            site=x_sync_site,
                                            peer_realm=sync_conn.peer.realm,
                                            peer_site=sync_conn.peer.site,
                                            sync_time=x_sync_time,
                                            skip_list=x_skip_list,
                                            skip_admin=x_skip_admin,
                                            object_types=x_object_types,
                                            checksum=config.SYNCING_STATUS_STRING)
                exception = None
            except OTPmeException as e:
                exception = str(e)
            if exception:
                log_msg = exception
                self.logger.warning(log_msg)
            else:
                log_msg = reply
                self.logger.debug(log_msg)

        # Close sync connection.
        sync_conn.close()

        if not status:
            log_msg = _("Error sending sync notification to {realm}/{site}: {reply}", log=True)[1]
            log_msg = log_msg.format(realm=realm, site=site, reply=reply)
            self.logger.warning(log_msg)
            return False

        # Update last notify timestamp.
        self.last_notify[last_notify_id] = time.time()

        return reply

    @handle_sync_child()
    def sync_sites(self, **kwargs):
        """ Make sure our sites list is in sync with the master site. """
        if config.realm_master_node:
            return
        # Acquire sync lock.
        sync_lock = self.acquire_sync_lock("objects")
        try:
            self._sync_sites()
        except Exception as e:
            log_msg = _("Failed to sync sites: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            self.logger.critical(log_msg)
        finally:
            sync_lock.release_lock()

    def _sync_sites(self, **kwargs):
        """ Make sure our sites list is in sync with the master site. """
        sync_status = True
        # Handle multiprocessing stuff.
        multiprocessing.atfork(exit_on_signal=True)
        # Setup logger.
        self.logger = log.setup_logger(pid=True)
        # Set proctitle for new child process.
        self.set_proctitle(sync_type="sync_sites", resync=False)

        #if config.host_data['type'] == "node":
        #    if not config.cluster_quorum:
        #        log_msg = ("Not starting sync of sites: No cluster quorum", log=True)[1]
        #        self.logger.warning(log_msg)
        #        return

        if config.master_node:
            # Master nodes of non-master sites must connect to master site.
            master_site = backend.get_object(object_type="site",
                                    uuid=config.realm_master_uuid)
            if not master_site:
                msg = _("Cannot find master site: {uuid}")
                msg = msg.format(uuid=config.realm_master_uuid)
                raise OTPmeException(msg)
            connect_sites = [master_site]
        else:
            # Non-master nodes must always connect to the master node of their
            # own site.
            own_site = backend.get_object(object_type="site",
                                         uuid=config.site_uuid)
            if not own_site:
                msg = _("Cannot find own site: {uuid}")
                msg = msg.format(uuid=config.site_uuid)
                raise OTPmeException(msg)
            connect_sites = [own_site]

        # Remove unneeded sites.
        for site in list(connect_sites):
            # Skip disabled sites.
            if not site.enabled:
                connect_sites.remove(site)
                continue
            # Skip sites we disabled sync for.
            if not site.sync_enabled:
                connect_sites.remove(site)
                continue
            # We must not connect to ourselves.
            if config.master_node:
                if site.uuid == config.site_uuid:
                    connect_sites.remove(site)
                    continue

        # If we got no sites to connect to we have nothing to do.
        if len(connect_sites) == 0:
            self.update_realm_data()
            return True

        log_msg = _("Starting sync of realms/sites...", log=True)[1]
        self.logger.debug(log_msg)

        sync_sites = {}
        reached_sites = []
        removed_objects = 0
        for site in connect_sites:
            # Connect to site master node.
            try:
                sync_conn = self.get_sync_connection(realm=site.realm,
                                                    site=site.name)
            except Exception as e:
                log_msg = _("Error getting sync connection: {error}", log=True)[1]
                log_msg = log_msg.format(error=e)
                self.logger.warning(log_msg)
                sync_status = False
                continue

            # Get sync parameters.
            this_host = backend.get_object(uuid=config.uuid)
            sync_params = this_host.get_sync_parameters(config.realm, site.name, sync_conn.peer.uuid)

            # Get sites from master node.
            status, \
            status_code, \
            reply, \
            binary_data = sync_conn.send("get_sites", command_args=sync_params)

            if status_code != status_codes.OK:
                log_msg = _("Error receiving sites list: {site}: {reply}", log=True)[1]
                log_msg = log_msg.format(site=site.oid, reply=reply)
                self.logger.warning(log_msg)
                sync_conn.close()
                sync_status = False
                continue

            # Close sync connection.
            sync_conn.close()

            # Get sites and their objects from reply.
            for x in reply:
                site_oid = oid.get(object_id=x)
                if site_oid != site.oid:
                    log_msg = _("Uuuh received wrong site object from site {site}: {site_oid}", log=True)[1]
                    log_msg = log_msg.format(site=site.oid, site_oid=site_oid)
                    self.logger.critical(log_msg)
                    continue
                # Will hold all valid site objects.
                site_objects = []
                # Get object configs from reply.
                x_objects = reply[site_oid]
                # Load and verify all site objects.
                for x in x_objects:
                    # Get object ID.
                    object_id = oid.get(object_id=x[0])
                    # Get object config.
                    encoded_config = x[1]
                    object_config = json.decode(encoded_config, encoding="hex")
                    # Load instance.
                    try:
                        o = backend.get_instance_from_oid(object_id, object_config)
                    except Exception as e:
                        log_msg = _("Failed to load object: {object_id}: {error}", log=True)[1]
                        log_msg = log_msg.format(object_id=object_id, error=e)
                        self.logger.critical(log_msg)
                        continue
                    # Make sure the object is valid.
                    try:
                        validate_received_object(site_oid, o)
                    except Exception as e:
                        log_msg = _("Received invalid object: {error}", log=True)[1]
                        log_msg = log_msg.format(error=e)
                        self.logger.critical(log_msg)
                        continue
                    # Add object to list.
                    site_objects.append(o)

                # Add site objects.
                if site_objects:
                    sync_sites[site_oid] = site_objects
            # Remember all sites we reached. We use this to prevent deleting
            # unreachable sites below.
            reached_sites.append(site.oid)

        # If we got no sync sites (e.g. realm master node with no other sites)
        # we have nothing to do.
        if len(sync_sites) == 0:
            if sync_status:
                self.update_realm_data()
                return True
            return False

        # Add/update sites and objects.
        added_objects = 0
        updated_objects = 0
        for site_oid in sync_sites:
            # Add site and objects we need to start the sync (e.g. master
            # node).
            for o in sync_sites[site_oid]:
                # Get OID.
                x_oid = o.oid
                # Get object config to write to backend.
                object_config = o.object_config.copy()
                # Get current object.
                x_object = backend.get_object(object_id=x_oid)
                if x_object:
                    # Get object type.
                    object_type = o.type
                    # No need to update object if checksum matches.
                    sync_checksum = backend.get_sync_checksum(x_oid)
                    if sync_checksum == o.sync_checksum:
                        continue
                    if config.master_node:
                        # Realm/site objects need some special handling (e.g.
                        # preserve auth/sync settings.
                        if object_type == "realm" or object_type == "site":
                            # Preserve auth/sync settings.
                            o.auth_enabled = x_object.auth_enabled
                            o.sync_enabled = x_object.sync_enabled
                            # Update object config.
                            o._set_variables()
                            o.set_variables()
                            o.update_object_config()
                            # Get object config of updated object.
                            object_config = o.object_config.copy()
                    # Update sync checksum of object.
                    object_config['SYNC_CHECKSUM'] = o.sync_checksum
                    updated_objects += 1
                    log_msg = _("Updating object: {oid}", log=True)[1]
                    log_msg = log_msg.format(oid=x_oid)
                    self.logger.info(log_msg)
                else:
                    log_msg = _("Adding new object: {oid}", log=True)[1]
                    log_msg = log_msg.format(oid=x_oid)
                    self.logger.info(log_msg)
                    added_objects += 1

                # Write object to backend. We cannot use o._write() because this
                # triggers other things we do not want/need on sync.
                try:
                    backend.write_config(object_id=x_oid,
                                    object_config=object_config,
                                    full_data_update=True,
                                    full_index_update=True,
                                    full_ldif_update=True)
                except Exception as e:
                    log_msg = _("Failed to write object: {oid}: {error}", log=True)[1]
                    log_msg = log_msg.format(oid=x_oid, error=e)
                    self.logger.critical(log_msg)
                    config.raise_exception()

        # Nodes must not delete realms/sites as they are deleted by clusterd.
        if self.host_type == "node":
            if sync_status:
                self.update_realm_data()
            return True

        # Remove remote missing sites.
        if self.host_type == "host":
            local_sites = backend.search(object_type="site",
                                        attribute="uuid",
                                        value="*",
                                        return_type="instance")
            for site in local_sites:
                # If the site is in the list of sites we received from master node
                # there is no need to remove it.
                if site.oid in sync_sites:
                    continue

                # We will not delete our own site. :)
                if site.uuid == config.site_uuid:
                    continue

                # The realm master site also must always exist.
                if site.uuid == config.realm_master_uuid:
                    log_msg = _("Uuuhh peer node tells us our master site does not exist anymore.", log=True)[1]
                    self.logger.warning(log_msg)
                    continue

                log_msg = _("Removing orphan site: {site}", log=True)[1]
                log_msg = log_msg.format(site=site.oid)
                self.logger.info(log_msg)

                site.delete(force=True, verify_acls=False)
                removed_objects += 1

        # Remove orphan realms.
        if self.host_type == "host":
            local_realms = backend.search(object_type="realm",
                                        attribute="uuid",
                                        value="*",
                                        return_type="instance")
            for realm in local_realms:
                realm_sites = backend.search(realm=realm.name,
                                            object_type="site",
                                            attribute="uuid",
                                            value="*",
                                            return_type="full_oid")
                # If the realm does not have a site anymore we can delete it.
                if len(realm_sites) == 0:
                    log_msg = _("Removing orphan realm: {realm}", log=True)[1]
                    log_msg = log_msg.format(realm=realm.oid)
                    self.logger.info(log_msg)
                    realm.delete(force=True, verify_acls=False)
                    removed_objects += 1

        if added_objects > 0 or updated_objects > 0 or removed_objects >0:
            log_method = self.logger.info
        else:
            log_method = self.logger.debug
        log_msg = _("Realms/sites sync finished: adds: {added} updates: {updated_objects} removes: {removed_objects}", log=True)[1]
        log_msg = log_msg.format(added=added_objects,
                        updated_objects=updated_objects,
                        removed_objects=removed_objects)
        log_method(log_msg)

        if sync_status:
            self.update_realm_data()
            return True

        return False

    def start_sync_job_from_queue(self):
        """ Start sync jobs from queue. """
        # We want to start oldest jobs first.
        sync_jobs = list(self.sync_jobs)
        sync_jobs.reverse()
        # Check if there is already a sync job of this type.
        sync_job = None
        for x in sync_jobs:
            sync_type = x['sync_type']
            try:
                sync_child = self._sync_childs[sync_type]
            except:
                sync_child = None

            if not sync_child:
                self.sync_jobs.remove(x)
                sync_job = x
                break

        if not sync_job:
            return

        # Load sync job.
        try:
            site = sync_job['site']
        except KeyError:
            log_msg = _("Got invalid sync job: Missing site", log=True)[1]
            self.logger.warning(log_msg)
            return
        try:
            realm = sync_job['realm']
        except KeyError:
            log_msg = _("Got invalid sync job: Missing realm", log=True)[1]
            self.logger.warning(log_msg)
            return
        try:
            resync = sync_job['resync']
        except KeyError:
            log_msg = _("Got invalid sync job: Missing resync", log=True)[1]
            self.logger.warning(log_msg)
            return
        try:
            offline = sync_job['offline']
        except KeyError:
            log_msg = _("Got invalid sync job: Missing offline", log=True)[1]
            self.logger.warning(log_msg)
            return
        try:
            sync_type = sync_job['sync_type']
        except KeyError:
            log_msg = _("Got invalid sync job: Missing sync type", log=True)[1]
            self.logger.warning(log_msg)
            return
        try:
            nsscache_resync = sync_job['nsscache_resync']
        except KeyError:
            log_msg = _("Got invalid sync job: Missing nsscache_resync", log=True)[1]
            self.logger.warning(log_msg)
            return

        log_msg = _("Starting sync job from queue: {sync_type}", log=True)[1]
        log_msg = log_msg.format(sync_type=sync_type)
        self.logger.debug(log_msg)

        self.start_sync(sync_type=sync_type,
                        queue=False,
                        resync=resync,
                        offline=offline,
                        nsscache_resync=nsscache_resync,
                        realm=realm, site=site)

    def start_sync(self, sync_type="objects", queue=True, resync=False,
        nsscache_resync=False, offline=False, realm=None, site=None, **kwargs):
        """ Start sync job as child process. """
        if sync_type == "sites" and queue:
            # Check for existing sync child.
            try:
                sync_child = self._sync_childs[sync_type]
            except:
                sync_child = None

            if sync_child:
                sync_job = {
                            "site"              : site,
                            "realm"             : realm,
                            "resync"            : resync,
                            "offline"           : False,
                            "sync_type"         : sync_type,
                            "nsscache_resync"   : nsscache_resync,
                            }
                if sync_job not in self.sync_jobs:
                    self.sync_jobs.append(sync_job)
                return

            # Create child process that will do the sync.
            sync_child = multiprocessing.start_process(name=self.name,
                                                target=self.sync_sites,
                                                join=True)
            # Add info.
            sync_child.info = sync_type
            # Add sync child.
            self.sync_childs[sync_type] = sync_child
            self._sync_childs[sync_type] = True
            log_msg = _("Started sync child: {info} [{pid}]", log=True)[1]
            log_msg = log_msg.format(info=sync_child.info, pid=sync_child.pid)
            self.logger.debug(log_msg)
            return

        # Default sync site is our own site (e.g. to sync token data)
        sync_sites = [ config.site_uuid ]
        # Update our host object from backend.
        self.reload_host_object()

        # Objects must be synced for all sites or the given realm/site.
        if sync_type == "objects":
            if realm and site:
                attribute = "name"
                value = site
            else:
                attribute = "uuid"
                value = "*"

            sync_sites = backend.search(object_type="site",
                                        attribute=attribute,
                                        value=value,
                                        return_type="uuid",
                                        realm=realm)
            if not sync_sites:
                log_msg = None
                if realm and site:
                    log_msg = _("Got unknown sync site: {realm}/{site}", log=True)[1]
                    log_msg = log_msg.format(realm=realm, site=site)
                elif realm:
                    log_msg = _("Got unknown sync realm: {realm}", log=True)[1]
                    log_msg = log_msg.format(realm=realm)
                if log_msg:
                    self.logger.warning(log_msg)

        # Dont sync objects from own site. This is done by clusterd.
        if self.host_type == "node":
            if sync_type == "objects":
                for site_uuid in list(sync_sites):
                    if site_uuid != config.site_uuid:
                        continue
                    sync_sites.remove(site_uuid)

        if offline:
            if os.path.exists(config.offline_dir):
                for uuid in os.listdir(config.offline_dir):
                    if not stuff.is_uuid(uuid):
                        continue
                    user = backend.get_object(uuid=uuid)
                    if not user:
                        continue
                    if user.site_uuid in sync_sites:
                        continue
                    sync_sites.append(user.site_uuid)

        # Start sync child processes.
        for site_uuid in sync_sites:
            try:
                site = backend.get_object(object_type="site", uuid=site_uuid)
            except LockWaitTimeout:
                continue
            if not site:
                log_msg = _("Cannot sync with unknown site: {site_uuid}", log=True)[1]
                log_msg = log_msg.format(site_uuid=site_uuid)
                self.logger.warning(log_msg)
                continue
            if not site.enabled:
                log_msg = _("Ignoring disabled site: {site}", log=True)[1]
                log_msg = log_msg.format(site=site.oid)
                self.logger.info(log_msg)
                continue
            if not site.sync_enabled:
                log_msg = _("Synchronization disabled for site: {site}", log=True)[1]
                log_msg = log_msg.format(site=site.oid)
                self.logger.info(log_msg)
                continue

            # Check for existing sync child.
            try:
                sync_child = self._sync_childs[sync_type]
            except:
                sync_child = None

            if sync_child and queue:
                sync_job = {
                            "site"              : site.name,
                            "realm"             : site.realm,
                            "resync"            : resync,
                            "sync_type"         : sync_type,
                            "offline"           : offline,
                            "nsscache_resync"   : nsscache_resync,
                            }
                if sync_job not in self.sync_jobs:
                    self.sync_jobs.append(sync_job)
                continue

            # Create child process that will do the sync.
            sync_child = multiprocessing.start_process(name=self.name,
                                                target=self._start_sync,
                                                target_args=(site.realm,
                                                        site.name,
                                                        sync_type,
                                                        resync,
                                                        nsscache_resync,
                                                        offline,),
                                                target_kwargs=kwargs,
                                                join=True)
            # Add realm/site.
            child_info = sync_type
            child_info = f"{child_info} ({site})"
            sync_child.info = child_info
            # Add sync child.
            self.sync_childs[sync_type] = sync_child
            self._sync_childs[sync_type] = True
            log_msg = _("Started sync child: {info} [{pid}]", log=True)[1]
            log_msg = log_msg.format(info=sync_child.info, pid=sync_child.pid)
            self.logger.debug(log_msg)

    @handle_sync_child()
    def _start_sync(self, realm, site, sync_type="objects",
        resync=False, nsscache_resync=False, offline=False,
        sync_from_command=False, **kwargs):
        """ Start sync. """
        # Handle multiprocessing stuff.
        multiprocessing.atfork(exit_on_signal=True)
        # Reconfigure logger to add sync type.
        log_banner = f"{config.log_name}:(sync:{sync_type})"
        self.logger = log.setup_logger(pid=True, banner=log_banner)
        # Set proctitle for new child process.
        if nsscache_resync:
            self.set_proctitle(sync_type=sync_type,
                                resync=True,
                                realm=realm,
                                site=site)
        elif resync:
            self.set_proctitle(sync_type=sync_type,
                                resync=True,
                                realm=realm,
                                site=site)
            nsscache_resync = True
        else:
            self.set_proctitle(sync_type=sync_type,
                                resync=False,
                                realm=realm,
                                site=site)

        # Update sync start timestamp.
        config.update_sync_status(realm=realm,
                                site=site,
                                status="running",
                                sync_type=sync_type,
                                progress=0)

        # For any remote sync we have to wait until a running realms/sites sync
        # job has finished.
        if sync_type != "nsscache":
            while True:
                try:
                    sites_sync_child = self._sync_childs['sites']
                except:
                    sites_sync_child = None
                if not sites_sync_child:
                    break
                time.sleep(0.01)

        # Start sync.
        sync_status = None
        if sync_type != "nsscache" and sync_type != "notify":
            force_site_address = False
            if sync_type == "token_counters":
                force_site_address = True
            if sync_type == "used_otps":
                force_site_address = True
            can_sync = False
            # Try to get connect to sync daemon.
            try:
                sync_conn = self.get_sync_connection(realm=realm,
                                                    site=site,
                                force_site_address=force_site_address)
                can_sync = True
            except HostDisabled as e:
                log_msg = _("Host disabled: {error}", log=True)[1]
                log_msg = log_msg.format(error=e)
                self.logger.warning(log_msg)
                # Disable ourselves based on peer reply.
                if self.host.type == "host":
                    if self.host.enabled:
                        log_msg = _("Disabling ourselves...", log=True)[1]
                        self.logger.info(log_msg)
                        try:
                            self.host.disable(verify_acls=False, force=True)
                        except Exception as e:
                            log_msg = _("Failed to disable host: {error}", log=True)[1]
                            log_msg = log_msg.format(error=e)
                            self.logger.critical(log_msg)
                        lock_caller = "hostd_sync"
                        self.host.acquire_lock(lock_caller=lock_caller)
                        self.host._write()
                        self.host.release_lock(lock_caller=lock_caller)
                        # Clear caches because hosts are read-only and cache
                        # orphans are detected by their checksums.
                        if self.host.type == "host":
                            cache.clear(self.host.oid)
                # Update sync status.
                config.update_sync_status(realm=realm,
                                        site=site,
                                        status="disabled",
                                        sync_type=sync_type)
                return True
            except Exception as e:
                sync_conn = None
                log_msg = _("Connection to syncd failed: {error}", log=True)[1]
                log_msg = log_msg.format(error=e)
                self.logger.warning(log_msg, exc_info=True)
                # Update sync status.
                config.update_sync_status(realm=realm,
                                        site=site,
                                        status="failed",
                                        sync_type=sync_type)
                # Objects sync have to merge orphan sync cache.
                if sync_type != "objects":
                    return False
                can_sync = True

            # We have to continue without sync connection to get policies
            # handled (e.g. update SSH authorized_keys files when login
            # times are restricted).
            if can_sync:
                resync_token_data = False
                if sync_type == "objects":
                    # Re-enable host if connection was successful.
                    if self.host.type == "host":
                        if not self.host.enabled:
                            log_msg = _("Enabling ourselves...", log=True)[1]
                            self.logger.info(log_msg)
                            self.host.enable(verify_acls=False, force=True)
                            lock_caller = "hostd_sync_objects"
                            self.host.acquire_lock(lock_caller=lock_caller)
                            self.host._write()
                            self.host.release_lock(lock_caller=lock_caller)
                            # Clear caches because hosts are read-only and cache
                            # orphans are detected by their checksums.
                            if self.host.type == "host":
                                cache.clear(self.host.oid)
                            resync_token_data = True

                # Get sync protocol.
                if sync_conn:
                    sync_proto = sync_conn.protocol
                else:
                    sync_cache = SyncCache(realm, site)
                    sync_proto = sync_cache.protocol
                    if sync_proto:
                        log_msg = _("Sync connection failed. Trying to merge orphan sync cache.", log=True)[1]
                        self.logger.info(log_msg)

                # Cannot sync without protocol version.
                if not sync_proto:
                    return

                # Get protocol handler.
                proto_class = protocols.client.get_class(sync_proto)
                # Create protocol handler.
                proto_handler = proto_class(connection=sync_conn)
                # Ignore changed objects?
                ignore_changed_objects = config.hostd_sync_ignore_changed_objects
                # Sync last used timestamps?
                sync_last_used = False
                if self.host_type == "node":
                    sync_last_used = True
                # Add sync job to running jobs to prevent master failover
                # while jobs are running.
                job_uuid = stuff.gen_uuid()
                job_name = f"Sync: {sync_type}"
                multiprocessing.running_jobs[job_uuid] = {
                                                        'name'      : job_name,
                                                        'start_time': time.time(),
                                                        'auth_token': "hostd",
                                                        'pid'       : os.getpid(),
                                                        }
                # Start sync job.
                try:
                    sync_status = proto_handler.do_sync(sync_type=sync_type,
                                    realm=realm,
                                    site=site,
                                    resync=resync,
                                    offline=offline,
                                    sync_last_used=sync_last_used,
                                    ignore_changed_objects=ignore_changed_objects)
                except SyncDisabled:
                    log_msg = _("Synchronization disabled by site: {realm}/{site}", log=True)[1]
                    log_msg = log_msg.format(realm=realm, site=site)
                    self.logger.info(log_msg)
                    # Update sync status.
                    config.update_sync_status(realm=realm,
                                            site=site,
                                            status="disabled",
                                            sync_type=sync_type)
                    # If sync is disabled we need a clean exit status as it is
                    # not a failure.
                    return True
                except ConnectionQuit as e:
                    log_msg = _("Connection lost running sync: {sync_type}: {error}", log=True)[1]
                    log_msg = log_msg.format(sync_type=sync_type, error=e)
                    self.logger.warning(log_msg, exc_info=True)
                    return False
                except Exception as e:
                    log_msg = _("Error running sync: {realm}/{site}: {sync_type}: {error}", log=True)[1]
                    log_msg = log_msg.format(realm=realm, site=site, sync_type=sync_type, error=e)
                    self.logger.critical(log_msg, exc_info=True)
                    # Update sync status.
                    config.update_sync_status(realm=realm,
                                            site=site,
                                            status="failed",
                                            sync_type=sync_type)
                    return False
                finally:
                    if sync_conn:
                        sync_conn.close()
                    multiprocessing.running_jobs.pop(job_uuid)

                # Start sync of other objects if required.
                if resync_token_data:
                    self._send_local_daemon_msg("sync_token_data")
                    self._send_local_daemon_msg("sync_ssh_authorized_keys")

        # Make sure nsscache is up-to-date.
        start_nsscache_sync = False
        if sync_type == "nsscache":
            start_nsscache_sync = True

        if sync_type == "objects":
            start_nsscache_sync = True

        # Do not run nsscache sync of own site on nodes. They get triggered by clusterd.
        if start_nsscache_sync:
            if not sync_from_command:
                if self.host_type == "node":
                    if realm == config.realm:
                        if site == config.site:
                            start_nsscache_sync = False

        ## Skip nsscache sync if last object creation was within the last 30 seconds.
        #if start_nsscache_sync:
        #    min_seconds = 10
        #    now = time.time()
        #    data_revision = config.get_data_revision()
        #    age = now - data_revision
        #    if age < min_seconds:
        #        log_msg = _("Not starting nsscache sync because last object was written within the last {min_seconds} seconds.", log=True)[1]
        #        log_msg = log_msg.format(min_seconds=min_seconds)
        #        self.logger.info(log_msg)
        #        start_nsscache_sync = False

        if start_nsscache_sync:
            # Acquire sync lock.
            sync_lock = self.acquire_sync_lock("sync_nsscache")
            # Set proctitle when syncing nsscache.
            self.set_proctitle(sync_type="nsscache",
                                resync=resync,
                                realm=realm,
                                site=site)

            # Add sync job to running jobs to prevent master failover
            # while jobs are running.
            job_uuid = stuff.gen_uuid()
            job_name = "Sync: nsscache"
            multiprocessing.running_jobs[job_uuid] = {
                                                    'name'      : job_name,
                                                    'start_time': time.time(),
                                                    'auth_token': "hostd",
                                                    'pid'       : os.getpid(),
                                                    }
            nsscache_sync_status = False
            try:
                nsscache_sync_status = nsscache.update(realm,
                                                    site,
                                                    resync=resync,
                                                    cache_resync=nsscache_resync,
                                                    lock=sync_lock)
                # On nssache sync from other sites we also have to sync nsscache
                # of our site (e.g. token is in role/group of our site).
                if site != config.site:
                    nsscache_sync_status = nsscache.update(config.realm,
                                                        config.site,
                                                        resync=resync,
                                                        cache_resync=nsscache_resync,
                                                        lock=sync_lock)
            except Exception as e:
                nsscache_sync_status = False
                log_msg = _("Error updating nsscache: {error}", log=True)[1]
                log_msg = log_msg.format(error=e)
                self.logger.critical(log_msg)
                #config.raise_exception()
            finally:
                # Release sync lock.
                sync_lock.release_lock()
                multiprocessing.running_jobs.pop(job_uuid)

            if sync_status is None:
                sync_status = nsscache_sync_status

        # Make sure SSH authorized keys files are up-to-date.
        if sync_type == "objects" or sync_type == "ssh_authorized_keys":
            # Acquire sync lock. We use the same lock ID to prevent a race
            # condition with sync when updating SSH authorized_keys.
            sync_lock = self.acquire_sync_lock("sync_ssh_authorized_keys")
            # Update authorized keys.
            if sync_lock:
                try:
                    ssh_sync_status = ssh.update_authorized_keys()
                except Exception as e:
                    ssh_sync_status = False
                    log_msg = _("Failed to update SSH authorized_keys: {error}", log=True)[1]
                    log_msg = log_msg.format(error=e)
                    self.logger.critical(log_msg, exc_info=True)
                finally:
                    # Release sync lock.
                    sync_lock.release_lock()

            if sync_status is None:
                sync_status = ssh_sync_status

        # Make sure we sent sync notifications to unsynchronized peers.
        if sync_type == "notify" and self.host_type == "node" and config.master_node:
            try:
                notify_sites = self.get_unsync_sites(timeout=self.lock_timeout)
            except LockWaitTimeout:
                if config.debug_level() > 3:
                    log_msg = _("Timeout waiting for lock getting unsync peers.", log=True)[1]
                    self.logger.warning(log_msg)
                notify_sites = None
            if notify_sites:
                notify_status = None
                for x in notify_sites:
                    # No need to notify sites we disabled sync for.
                    if not x.sync_enabled:
                        log_msg = _("Not sending notify to site we disabled sync for.", log=True)[1]
                        self.logger.debug(log_msg)
                        continue
                    try:
                        site_status = self.sync_notify(realm=x.realm, site=x.name)
                    except Exception as e:
                        site_status = False
                        log_msg = _("Error sending sync notify: {dest}: {error}", log=True)[1]
                        log_msg = log_msg.format(dest=x, error=e)
                        self.logger.warning(log_msg)
                        config.raise_exception()

                    if site_status is False and notify_status is None:
                        notify_status = False

                if sync_status is None:
                    sync_status = notify_status

            else:
                if config.master_node:
                    log_msg = _("Not sending sync notification: All peers are in sync", log=True)[1]
                else:
                    log_msg = _("Not sending sync notification: We are not the master node", log=True)[1]
                self.logger.debug(log_msg)

        # Update status of last sync.
        try:
            config.update_sync_status(realm=realm,
                                    site=site,
                                    status=sync_status,
                                    sync_type=sync_type)
        except Exception as e:
            config.raise_exception()
            log_msg = _("Failed to update sync status: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            self.logger.critical(log_msg)
            sync_status = False

        # Make sure we send sync notifications to all non-master nodes.
        if config.master_node:
            if sync_status:
                if sync_type == "objects":
                    all_nodes = backend.search(object_type="node",
                                                attribute="uuid",
                                                value="*",
                                                realm=config.realm,
                                                site=config.site,
                                                return_type="instance")
                    for node in all_nodes:
                        if node.oid == self.host.oid:
                            continue
                        if not node.enabled:
                            continue
                        try:
                            self.sync_notify(realm=realm, site=site, node=node.oid)
                        except Exception as e:
                            log_msg = _("Error sending sync notify: {node}: {error}", log=True)[1]
                            log_msg = log_msg.format(node=node, error=e)
                            self.logger.warning(log_msg)
                            config.raise_exception()

        # Handle exit status.
        if sync_status:
            return True
        if sync_status is None:
            return True
        return False

    def process_spooled_logs(self):
        try:
            process_spooled_logs()
        except Exception as e:
            log_msg = _("Failed to resend spooled audit log entries: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            self.logger.warning(log_msg)

    def update_crls(self):
        """ Update CA CRLs. """
        if not config.master_node:
            return
        if not config.cluster_status:
            return
        if config.master_failover:
            return
        result = backend.search(object_type="ca",
                                attribute="uuid",
                                value="*",
                                realm=config.realm,
                                site=config.site,
                                return_type="instance")
        for ca in result:
            crl_age = time.time() - ca.last_crl_update
            if crl_age < 86400:
                continue
            callback = config.get_callback()
            ca.update_crl(verify_acls=False,
                        no_audit_log=True,
                        callback=callback)
            if not config.master_node:
                continue
            if not config.cluster_status:
                continue
            if config.master_failover:
                continue
            callback.write_modified_objects()
            callback.release_cache_locks()

    def run_resolvers(self):
        """ Run resolvers as child process. """
        if not config.master_node:
            return
        if self.resolver_run_child:
            if self.resolver_run_child.is_alive():
                return
            self.resolver_run_child.join()
            self.resolver_run_child.close()
        # Create child process.
        child = multiprocessing.start_process(name=self.name,
                            target=self._run_resolvers)
        self.resolver_run_child = child

    def _run_resolvers(self):
        """ Run resolvers. """
        # Set proctitle for new child process.
        self.set_proctitle(proctitle="Run resolvers")
        # Handle multiprocessing stuff.
        multiprocessing.atfork(exit_on_signal=True)
        # Setup logger.
        self.logger = log.setup_logger(pid=True)
        resolvers = backend.search(object_type="resolver",
                                    attribute="uuid",
                                    value="*",
                                    return_type="instance",
                                    realm=config.realm,
                                    site=config.site)
        for resolver in resolvers:
            if not config.master_node:
                break
            if not resolver.enabled:
                continue
            now = time.time()
            if (now - resolver.last_run) < resolver.sync_interval:
                continue
            log_msg = _("Running resolver: {resolver}", log=True)[1]
            log_msg = log_msg.format(resolver=resolver.oid)
            self.logger.info(log_msg)
            callback = config.get_callback()
            callback.disable()
            resolver.run(daemon_run=True,
                        interactive=False,
                        verify_acls=False,
                        callback=callback)
        # Do some cleanup.
        multiprocessing.cleanup()

    def clear_outdated_cache_objects(self):
        """ Start clear outdated cache objects als child process. """
        if self.clear_outdated_cache_objects_child:
            if self.clear_outdated_cache_objects_child.is_alive():
                return
            self.clear_outdated_cache_objects_child.join()
            self.clear_outdated_cache_objects_child.close()
        # Create child process.
        child = multiprocessing.start_process(name=self.name,
                            target=self._clear_outdated_cache_objects)
        self.clear_outdated_cache_objects_child = child

    def _clear_outdated_cache_objects(self):
        """ Clear outdated cache objects. """
        # Set proctitle for new child process.
        self.set_proctitle(proctitle="Remove outdated cache objects")
        # Handle multiprocessing stuff.
        multiprocessing.atfork(exit_on_signal=True)
        # Clear cache objects.
        cache.clear_outdated_acl_cache()
        backend.clear_outdated_sync_maps()
        # Do some cleanup.
        multiprocessing.cleanup()

    def remove_outdated_tokens(self):
        """ Start remove outdated offline tokens job as child process. """
        if self.remove_outdated_tokens_child:
            if self.remove_outdated_tokens_child.is_alive():
                return
            self.remove_outdated_tokens_child.join()
            self.remove_outdated_tokens_child.close()
        # Create child process.
        child = multiprocessing.start_process(name=self.name,
                            target=self._remove_outdated_tokens)
        self.remove_outdated_tokens_child = child

    def _remove_outdated_tokens(self):
        """ Remove outdated offline tokens. """
        from otpme.lib.offline_token import OfflineToken
        # Set proctitle for new child process.
        self.set_proctitle(proctitle="Remove outdated tokens")
        # Handle multiprocessing stuff.
        multiprocessing.atfork(exit_on_signal=True)
        # Setup logger.
        self.logger = log.setup_logger(pid=True)
        try:
            user_uuids = os.listdir(config.offline_dir)
        except:
            user_uuids = []

        for uuid in user_uuids:
            # Ignore files etc.
            if not os.path.isdir(os.path.join(config.offline_dir, uuid)):
                continue
            # Ignore non-uuid dirs.
            if not stuff.is_uuid(uuid):
                continue
            # Ignore unknown UUIDs.
            if not backend.get_oid(object_type="user", uuid=uuid):
                continue
            # Set user we want to read offline tokens for.
            try:
                offline_token = OfflineToken()
                offline_token.set_user(uuid=uuid)
            except Exception as e:
                log_msg = _("Error loading offline tokens: {error}", log=True)[1]
                log_msg = log_msg.format(error=e)
                self.logger.critical(log_msg)
                continue
            # Acquire offline token lock.
            offline_token.lock()
            # Call load() which removes outdated tokens.
            try:
                offline_token.load()
            except Exception as e:
                log_msg = _("Error getting offline tokens: {error}", log=True)[1]
                log_msg = log_msg.format(error=e)
                self.logger.critical(log_msg)
            # Release offline token lock.
            offline_token.unlock()

        # Do some cleanup.
        multiprocessing.cleanup()

    def wait_for_syncd(self):
        """ Wait for syncd to get ready. """
        try:
            syncd_status = config.read_daemon_status("syncd")['status']
        except:
            syncd_status = False
        return syncd_status

    def start_sync_jobs(self):
        """ Wait for syncd to come up. """
        # On nodes we have to wait for the local syncd to come up.
        if self.host_type == "node":
            if not self.wait_for_syncd():
                return False
            if not config.cluster_status:
                return False

        # Start initial sync.
        if self.host_type == "node":
            self.start_sync(sync_type="sites")
            self.start_sync(sync_type="objects")
            self.start_sync(sync_type="ssh_authorized_keys")
            self.start_sync(sync_type="used_otps", offline=True)
            self.start_sync(sync_type="token_counters", offline=True)
            self.start_sync(sync_type="nsscache")
            if config.master_node:
                self.start_sync(sync_type="notify")
            #self.start_sync(sync_type="used_otps")
            #self.start_sync(sync_type="token_counters")
        else:
            self.start_sync(sync_type="sites")
            self.start_sync(sync_type="objects")
            self.start_sync(sync_type="nsscache")
            self.start_sync(sync_type="ssh_authorized_keys")
            self.start_sync(sync_type="used_otps", offline=True)
            self.start_sync(sync_type="token_counters", offline=True)

        return True

    def _run(self, **kwargs):
        """ Start daemon loop. """
        # Set process title.
        self.set_proctitle()
        # Set signal handler.
        signal.signal(signal.SIGTERM, self.signal_handler)
        signal.signal(signal.SIGINT, self.signal_handler)
        # Setup logger.
        self.logger = log.setup_logger(pid=True)
        # Timeout waiting for backend locks.
        self.lock_timeout = 10
        # Configure ourselves (e.g. certificates etc.).
        try:
            self.configure()
        except Exception as e:
            log_msg = _("Failed to configure {name}", log=True)[1]
            log_msg = log_msg.format(name=self.name)
            self.logger.critical(log_msg)
        # All protocols we support.
        self.protocols = config.get_otpme_protocols(self.name, server=True)
        # Timestamps of last successful sync.
        self.last_sync = {}
        self.last_sync['notify'] = 0
        self.last_sync['objects'] = 0
        self.last_sync['nsscache'] = 0
        self.last_sync['used_otps'] = 0
        self.last_sync['token_counters'] = 0
        self.last_sync['ssh_authorized_keys'] = 0
        # Timestamps of last failed sync.
        self.last_failed_sync = {}
        # Interval we will sync objects with master node.
        self.sync_interval = config.hostd_sync_interval
        # Interval we will retry failed sync.
        self.sync_retry_interval = config.hostd_sync_retry_interval
        # Will hold sync commands we get via socket.
        self.sync_by_command = []
        self.sync_by_command_opts = {}
        # Sync notification limit in seconds. (e.g. send sync notification max
        # each 5 seconds.)
        self.notify_limit = 5
        # FIXME: where to configure max_conn
        # set max client connections
        self.max_conn = 100
        # FIXME: where to configure socket banner?
        # Set socket banner.
        self.socket_banner = f"{status_codes.OK} {self.full_name} {config.my_version}"

        # Add default connection handler.
        try:
            self.set_connection_handler()
        except Exception as e:
            log_msg = _("Failed to set connection handler: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            self.logger.critical(log_msg)

        # Disable interactive policies (e.g. reauth).
        if not "interactive" in config.ignore_policy_tags:
            config.ignore_policy_tags.append("interactive")

        # Add hostd unix socket world read/writeable to allow users to get e.g.
        # realm/site from hostd.
        self.socket_path = config.hostd_socket_path
        try:
            self.add_socket(self.socket_path,
                            handler=self.conn_handler,
                            banner=self.socket_banner,
                            user=self.user,
                            group=self.group,
                            mode=0o666)
        except Exception as e:
            log_msg = _("Failed to add unix socket: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            self.logger.critical(log_msg)

        # We can drop privileges AFTER sockets are created. This is needed when
        # listening to well known ports (<1024), which requires root privileges.
        try:
            self.drop_privileges()
        except Exception as e:
            log_msg = _("Failed to drop privileges: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            self.logger.critical(log_msg)

        # Start listening on sockets.
        for s in self.sockets:
            try:
                s.listen()
            except Exception as e:
                log_msg = _("Unable to listen on socket: {error}", log=True)[1]
                log_msg = log_msg.format(error=e)
                self.logger.critical(log_msg)

        # Will hold child processes that sync objects from master node.
        self.sync_childs = {}
        # To make sync childes accessable to subprocesses we need a shared dict.
        # This dict will only include per sync child True/None, no process.
        try:
            self._sync_childs = multiprocessing.get_dict("hostd_sync_childs")
        except Exception as e:
            log_msg = _("Failed to get shared dict: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            self.logger.critical(log_msg)
        # Will hold all sync jobs.
        try:
            self.sync_jobs = multiprocessing.get_list("hostd_sync_jobs")
        except Exception as e:
            log_msg = _("Failed to get shared list: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            self.logger.critical(log_msg)

        # Per realm/site/node last sync notify timestamps.
        try:
            self.last_notify = multiprocessing.get_dict("hostd_last_notify")
        except Exception as e:
            log_msg = _("Failed to get shared dict: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            self.logger.critical(log_msg)

        # Notify controld that we are ready.
        try:
            self.comm_handler.send("controld", command="ready")
        except Exception as e:
            log_msg = _("Failed to send read message to controld: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            self.logger.critical(log_msg)

        # Get our host object.
        try:
            self.reload_host_object()
        except Exception as e:
            log_msg = _("Failed to reload host data: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            self.logger.critical(log_msg)

        log_msg = _("{full_name} started", log=True)[1]
        log_msg = log_msg.format(full_name=self.full_name)
        self.logger.info(log_msg)

        # Run in loop until we get signal.
        recv_timeout = None
        init_sync_started = False
        log_resend_interval = 60
        crl_update_interval = 300
        resolver_run_interval = 30
        cache_outdate_interval = 30
        host_object_reload_interval = 30
        token_data_removal_interval = 30
        last_resolver_run = time.time()
        last_log_resend_run = time.time()
        last_crl_update_run = time.time()
        last_cache_outdate = time.time()
        last_host_object_reload = time.time()
        last_token_data_removal = time.time()
        while True:
            # Start initial sync jobs.
            if not init_sync_started:
                try:
                    sync_start_status = self.start_sync_jobs()
                except Exception as e:
                    sync_start_status = False
                    log_msg = _("Failed to start sync jobs: {error}", log=True)[1]
                    log_msg = log_msg.format(error=e)
                    self.logger.error(log_msg)
                if sync_start_status:
                    init_sync_started = True

            try:
                # Calculate new recv timeout.
                new_timeout = min(crl_update_interval,
                                log_resend_interval,
                                resolver_run_interval,
                                cache_outdate_interval,
                                host_object_reload_interval,
                                token_data_removal_interval,
                                self.sync_interval)
                if recv_timeout is None:
                    recv_timeout = new_timeout
                recv_timeout = min(recv_timeout, new_timeout)

                # Try to read daemon message.
                try:
                    sender, \
                    daemon_command, \
                    data = self.comm_handler.recv(recv_timeout)
                except ExitOnSignal:
                    break
                except TimeoutReached:
                    daemon_command = None
                except Exception as e:
                    msg, log_msg = _("Error receiving daemon message: {error}", log=True)
                    msg = msg.format(error=e)
                    log_msg = log_msg.format(error=e)
                    self.logger.critical(log_msg, exc_info=True)
                    raise OTPmeException(msg)

                now = time.time()

                # Update our host object from backend.
                if (now - last_host_object_reload) >= host_object_reload_interval:
                    self.reload_host_object()
                    last_host_object_reload = time.time()

                # Remove outdated offline tokens.
                if (now - last_token_data_removal) >= token_data_removal_interval:
                    self.remove_outdated_tokens()
                    last_token_data_removal = time.time()

                # Clear outdated shared cache objects.
                if (now - last_cache_outdate) >= cache_outdate_interval:
                    self.clear_outdated_cache_objects()
                    last_cache_outdate = time.time()

                # Update CA CRLs.
                if (now - last_crl_update_run) >= crl_update_interval:
                    self.update_crls()
                    last_crl_update_run = time.time()

                # Run resolvers.
                if (now - last_resolver_run) >= resolver_run_interval:
                    self.run_resolvers()
                    last_resolver_run = time.time()

                # Retry spooled log entries.
                if (now - last_log_resend_run) >= log_resend_interval:
                    self.process_spooled_logs()
                    last_log_resend_run = time.time()

                # Check if command can be handled by parent class.
                if daemon_command is not None:
                    try:
                        self._handle_daemon_command(sender, daemon_command, data)
                    except UnknownCommand:
                        pass
                    except DaemonQuit:
                        break
                    except DaemonReload:
                        # FIXME: Get reload command via network to reload on changes of own host?
                        # Check for config changes.
                        restart = self.configure()
                        if restart:
                            break
                        # Inform controld that we finished our reload.
                        self.comm_handler.send("controld", command="reload_done")

                    if daemon_command == "sync_notify":
                        if "notify" not in self.sync_by_command:
                            self.sync_by_command.append('notify')
                    if daemon_command == "sync_sites":
                        if "notify" not in self.sync_by_command:
                            self.sync_by_command.append('sites')
                    if daemon_command == "sync_token_data":
                        if "used_otps" not in self.sync_by_command:
                            self.sync_by_command.append('used_otps')
                        if "token_counters" not in self.sync_by_command:
                            self.sync_by_command.append('token_counters')

                    # Object sync commands are a dict containing sync realm/site.
                    if "sync_objects" in daemon_command:
                        if "objects" not in self.sync_by_command:
                            self.sync_by_command.append('sites')
                            self.sync_by_command.append('objects')
                            self.sync_by_command_opts['objects'] = data

                    if "resync_objects" in daemon_command:
                        if "resync_objects" not in self.sync_by_command:
                            self.sync_by_command.append('resync_objects')
                            self.sync_by_command_opts['resync_objects'] = data

                    if daemon_command == "sync_nsscache":
                        if "nsscache" not in self.sync_by_command:
                            self.sync_by_command.append('nsscache')
                    if daemon_command == "resync_nsscache":
                        if "resync_nsscache" not in self.sync_by_command:
                            self.sync_by_command.append('resync_nsscache')
                    if daemon_command == "sync_ssh_authorized_keys":
                        if "sync_ssh_authorized_keys" not in self.sync_by_command:
                            self.sync_by_command.append('ssh_authorized_keys')

                child_list = list(self.sync_childs)
                if "sites" in child_list:
                    child_list.remove("sites")
                    child_list.insert(0, "sites")

                # Start sync process if needed.
                recv_timeout = None
                for sync_type in child_list:
                    # Handle still running and finished sync processes.
                    sync_child = self.sync_childs[sync_type]
                    if sync_child:
                        # If the sync job is still running notify ourselves
                        # (via "sync_done") to check again.
                        if sync_child.is_alive():
                            recv_timeout = 1
                            continue

                        # Check if we are disabled.
                        if self.host.enabled:
                            if sync_child.exitcode == 0:
                                normal_sync_interval = True
                            else:
                                normal_sync_interval = False
                        else:
                            normal_sync_interval = True

                        if normal_sync_interval:
                            self.last_sync[sync_type] = time.time()
                            self.last_failed_sync[sync_type] = None
                        else:
                            self.last_sync[sync_type] = None
                            self.last_failed_sync[sync_type] = time.time()

                        if sync_child.exitcode == 0:
                            log_msg = _("Sync child finished successful: {info} [{pid}]", log=True)[1]
                            log_msg = log_msg.format(info=sync_child.info, pid=sync_child.pid)
                            self.logger.debug(log_msg)
                        else:
                            log_msg = _("Sync child failed: {info} [{pid}]", log=True)[1]
                            log_msg = log_msg.format(info=sync_child.info, pid=sync_child.pid)
                            self.logger.debug(log_msg)

                        # Close sync child.
                        sync_child.close()

                        self.sync_childs[sync_type] = None
                        self._sync_childs[sync_type] = None

                    # If we got waked up by a "sync done" command and there is no
                    # other sync command in our queue there is no need to start
                    # a new sync job.
                    if daemon_command == "sync_done":
                        if sync_type not in self.sync_by_command:
                            continue

                    resync = False
                    sync_site = None
                    sync_realm = None
                    start_sync = False
                    nsscache_resync = False
                    # Check if we got sync commands via socket.
                    sync_from_command = False
                    if self.sync_by_command:
                        sync_from_command = True
                        # Check if we got the current sync type via command.
                        if sync_type in self.sync_by_command:
                            start_sync = True
                            self.sync_by_command.remove(sync_type)
                        # For object sync we need to handle special commands.
                        if sync_type == "objects":
                            if "resync_objects" in self.sync_by_command:
                                start_sync = True
                                resync = True
                                self.sync_by_command.remove("resync_objects")
                            if "resync_nsscache" in self.sync_by_command:
                                # If "resync_nsscache" is the only command
                                # we got set sync type.
                                if not start_sync:
                                    sync_type = "nsscache"
                                start_sync = True
                                nsscache_resync = True
                                self.sync_by_command.remove("resync_nsscache")

                            if resync:
                                sync_opts_name = "resync_objects"
                            else:
                                sync_opts_name = "objects"
                            try:
                                sync_realm = self.sync_by_command_opts[sync_opts_name]['realm']
                            except KeyError:
                                pass
                            try:
                                sync_site = self.sync_by_command_opts[sync_opts_name]['site']
                            except KeyError:
                                pass
                            try:
                                self.sync_by_command_opts.pop(sync_type)
                            except KeyError:
                                pass

                    else:
                        # While disabled we only try to sync objects.
                        if sync_type != "objects" and not self.host.enabled:
                            continue

                        # Check if we have to start sync by interval.
                        if self.last_failed_sync[sync_type] is None:
                            # Sync notifications are not timed by
                            # self.sync_interval.
                            if sync_type == "notify":
                                if self.host_type == "node":
                                    try:
                                        unsync_sites = self.get_unsync_sites(timeout=self.lock_timeout)
                                    except LockWaitTimeout:
                                        if config.debug_level() > 3:
                                            log_msg = _("Timeout waiting for lock getting unsync peers.", log=True)[1]
                                            self.logger.warning(log_msg)
                                        unsync_sites = None
                                    # We only need to start a notify job if there are any
                                    # unsynchronized sites/nodes.
                                    if unsync_sites:
                                        start_sync = True
                            else:
                                if (time.time() - self.last_sync[sync_type]) > self.sync_interval:
                                    start_sync = True
                        else:
                            if ((time.time() - self.last_failed_sync[sync_type]) > self.sync_retry_interval):
                                log_msg = _("Last sync failed and retry interval reached. Retrying...", log=True)[1]
                                self.logger.warning(log_msg)
                                start_sync = True

                    # Start sync job.
                    if start_sync:
                        if sync_type == "token_counters" \
                        or sync_type == "used_otps":
                            # Start sync of offline token data.
                            self.start_sync(sync_type=sync_type,
                                            resync=resync,
                                            nsscache_resync=nsscache_resync,
                                            realm=sync_realm,
                                            site=sync_site,
                                            offline=True)
                        else:
                            # Start sync job.
                            self.start_sync(sync_type=sync_type,
                                            resync=resync,
                                            nsscache_resync=nsscache_resync,
                                            sync_from_command=sync_from_command,
                                            realm=sync_realm,
                                            site=sync_site)

                # Start sync jobs from queue.
                self.start_sync_job_from_queue()

            except (KeyboardInterrupt, SystemExit):
                pass
            except Exception as e:
                log_msg = _("Unhandled error in hostd: {error}", log=True)[1]
                log_msg = log_msg.format(error=e)
                self.logger.critical(log_msg, exc_info=True)
                config.raise_exception()

        self.shutdown_sync_childs()
        log_msg = _("Received signal, terminating.", log=True)[1]
        self.logger.info(log_msg)
        # Cleanup multiprocessing.
        multiprocessing.cleanup()

    def shutdown_sync_childs(self):
        """ Shutdown sync childs. """
        child_list = list(self.sync_childs)

        if "sites" in child_list:
            child_list.remove("sites")
            child_list.insert(0, "sites")

        for sync_type in child_list:
            sync_child = self.sync_childs[sync_type]
            if not sync_child:
                continue
            if not sync_child.is_alive():
                self.sync_childs[sync_type] = None
                self._sync_childs[sync_type] = None
                continue

            # Send TERM signal to sync process.
            if sync_child.is_alive():
                sync_child.terminate()

            try:
                sync_child.close()
            except OSError:
                pass
            # We need to remove child from sync childs because this
            # may affect other running sync childs.
            self.sync_childs[sync_type] = None
            self._sync_childs[sync_type] = None

    def stop_resolvers(self):
        if not self.resolver_run_child:
            return
        if not self.resolver_run_child.is_alive():
            return
        self.resolver_run_child.terminate()
        self.resolver_run_child.join()
