# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
# Distributed under the terms of the GNU General Public License v2
import os
import time
import datetime
from prettytable import FRAME
from prettytable import NONE
from prettytable import PrettyTable

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import oid
from otpme.lib import stuff
#from otpme.lib import cache
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import locking
from otpme.lib import connections
from otpme.lib import sign_key_cache
from otpme.lib import multiprocessing
from otpme.lib.protocols import status_codes
from otpme.lib.daemon.clusterd import calc_node_vote
from otpme.lib.protocols.otpme_server import OTPmeServer1
from otpme.lib.freeradius import reload as freeradius_reload

from otpme.lib.exceptions import *

logger = config.logger


REGISTER_BEFORE = []
REGISTER_AFTER = ['otpme.lib.protocols.otpme_server']
PROTOCOL_VERSION = "OTPme-cluster-1.0"

def register():
    config.register_otpme_protocol("clusterd", PROTOCOL_VERSION, server=True)

class OTPmeClusterP1(OTPmeServer1):
    """ Class that implements OTPme-cluster-1.0. """
    def __init__(self, **kwargs):
        # Our name.
        self.name = "clusterd"
        # The protocol we support.
        self.protocol = PROTOCOL_VERSION
        # Indicates parent class that we need no authentication.
        self.require_auth = "host"
        self.require_preauth = False
        self.require_client_cert = True
        # Communication with hostd is only done via unix sockets.
        self.encrypt_session = True
        self.require_master_node = False
        # Call parent class init.
        OTPmeServer1.__init__(self, **kwargs)

    def _pre_init(self, *args, **kwargs):
        """ Init protocol handler. """
        # Our PID.
        self.pid = os.getpid()
        # Do atfork stuff.
        multiprocessing.atfork(quiet=True)

    def get_running_jobs(self):
        running_jobs = dict(multiprocessing.running_jobs)
        if len(running_jobs) == 0:
            return
        table_headers = ['Start Time', 'Job Name', 'Auth Token']
        table = PrettyTable(table_headers,
                            header_style="title",
                            vrules=NONE,
                            hrules=FRAME)
        table.align = "l"
        table.padding_width = 0
        table.right_padding_width = 1
        for x in running_jobs:
            x_name = running_jobs[x]['name']
            x_start_time = running_jobs[x]['start_time']
            x_start_time = datetime.datetime.fromtimestamp(x_start_time)
            x_auth_token = running_jobs[x]['auth_token']
            row = [x_start_time, x_name, x_auth_token]
            table.add_row(row)
        # Get output string from table.
        output = table.get_string(start=0)
        return output

    def verify_peer(self):
        """ Verify peer. """
        if self.peer.type != "node":
            msg = "Peer is not a node."
            raise OTPmeException(msg)
        if self.peer.realm != config.realm:
            msg = "Peer is not from our realm: %s" % self.peer.realm
            raise OTPmeException(msg)
        if self.peer.site != config.site:
            msg = "Peer is not from our site: %s" % self.peer.site
            raise OTPmeException(msg)
        if not self.peer.enabled:
            msg = "Peer is disabled: %s" % self.peer.name
            raise HostDisabled(msg)

    def _process(self, command, command_args):
        """ Handle commands received from host_handler. """
        # all valid commands
        valid_commands = [
                            "ping",
                            "sync",
                            "write",
                            "rename",
                            "delete",
                            "acquire_lock",
                            "release_lock",
                            "get_checksums",
                            "get_node_vote",
                            "set_node_sync",
                            "unset_node_sync",
                            "set_node_online",
                            "get_master_node",
                            "do_radius_reload",
                            "do_nsscache_sync",
                            "get_member_nodes",
                            "do_master_failover",
                            "get_cluster_quorum",
                            "get_cluster_status",
                            "set_master_failover",
                            "get_init_sync_status",
                            "get_node_sync_status",
                            "start_master_failover",
                            "get_master_sync_status",
                            "deconfigure_floating_ip",
                            "get_master_failover_status",
                        ]

        if command in valid_commands:
            pass
            #msg = ("Received command %s from client: %s"
            #        % (command, self.client))
            #logger.debug(msg)
        else:
            msg = ("Received unknown command %s from client: %s"
                    % (command, self.client))
            logger.warning(msg)

        # Make sure peer is a node from our site.
        try:
            self.verify_peer()
        except HostDisabled as e:
            status = status_codes.HOST_DISABLED
            message = "Failed to verify peer: %s: %s" % (self.peer, e)
            response = self.build_response(status, message, encrypt=False)
            return response
        except Exception as e:
            status = False
            message = "Failed to verify peer: %s: %s" % (self.peer, e)
            response = self.build_response(status, message, encrypt=False)
            return response

        # check if we got a valid command
        if not command in valid_commands:
            message = "Unknown command: %s" % command
            status = False

        elif command == "ping":
            message = "pong"
            status = True
            msg = "Received ping."
            logger.debug(msg)

        elif command == "get_master_node":
            try:
                message = multiprocessing.master_node['master']
                status = True
            except KeyError:
                message = None
                status = False

        elif command == "get_cluster_status":
            status = True
            message = config.cluster_status

        elif command == "get_cluster_quorum":
            status = True
            try:
                cluster_quorum = config.cluster_quorum
            except:
                cluster_quorum = False
            message = cluster_quorum
            if cluster_quorum:
                try:
                    message = multiprocessing.cluster_quorum['quorum']
                except KeyError:
                    message = cluster_quorum

        elif command == "get_master_sync_status":
            if config.host_data['name'] in multiprocessing.master_sync_done:
                status = True
                message = "Master sync done."
            else:
                status = False
                message = "Master sync not done."

        elif command == "get_init_sync_status":
            status = True
            message = "Init sync done."
            try:
                node_name = command_args['node_name']
            except:
                message = "Missing node name."
                status = False
            if status:
                if node_name not in multiprocessing.init_sync_done:
                    status = False

        elif command == "get_node_sync_status":
            if os.path.exists(config.node_sync_file):
                status = True
                message = "Node in sync."
            else:
                status = False
                message = "Node not in sync."

        elif command == "set_node_online":
            status = True
            message = "Node online."
            multiprocessing.online_nodes[self.peer.name] = True

        elif command == "set_node_sync":
            status = True
            message = "Node in sync."
            sync_time = command_args['sync_time']
            config.touch_node_sync_file(sync_time)

        elif command == "unset_node_sync":
            status = True
            message = "Node NOT in sync."
            config.remove_node_sync_file()

        elif command == "get_node_vote":
            status = True
            message = 0.0
            # Get/set vote for this node. This is also done in clusterd daemon.
            if config.cluster_vote_participation:
                node_vote = calc_node_vote()
                multiprocessing.node_votes[config.host_data['name']] = node_vote
                message = node_vote

        elif command == "get_member_nodes":
            status = True
            message = multiprocessing.member_nodes.keys()

        elif command == "get_checksums":
            status = True
            object_types = config.tree_object_types
            data_types = list(config.flat_object_types)
            data_types.remove("session")
            session_types = ['session']
            object_checksums, objects_checksum = backend.get_sync_list(realm=config.realm,
                                                                    site=config.site,
                                                                    object_types=object_types)
            data_checksums, data_checksum = backend.get_sync_list(realm=config.realm,
                                                                site=config.site,
                                                                object_types=data_types)
            session_checksums, sessions_checksum = backend.get_sync_list(realm=config.realm,
                                                                        site=config.site,
                                                                        object_types=session_types)
            message = {
                        'object_checksums'  : object_checksums,
                        'objects_checksum'  : objects_checksum,
                        'data_checksum'     : data_checksum,
                        'data_checksums'    : data_checksums,
                        'sessions_checksum' : sessions_checksum,
                        'session_checksums' : session_checksums,
                        }

        elif command == "sync":
            status = True
            message = None
            try:
                remote_objects = command_args['remote_objects']
            except:
                message = "Missing remote objects."
                status = False
            if status:
                object_types = config.get_cluster_object_types()
                result = backend.search(object_types=object_types,
                                        attribute="uuid",
                                        value="*",
                                        return_type="instance")
                sync_objects = {}
                for x in result:
                    sync_object = False
                    try:
                        remote_object_data = remote_objects[x.oid.full_oid]
                    except:
                        remote_object_data = None
                        sync_object = True
                    if remote_object_data:
                        remote_last_used = remote_object_data['last_used']
                        if remote_last_used is not None and x.last_used is not None:
                            if remote_last_used < x.last_used:
                                sync_object = True
                        remote_last_modified = remote_object_data['last_modified']
                        if remote_last_modified is not None and x.last_modified is not None:
                            if remote_last_modified < x.last_modified:
                                sync_object = True
                    if not sync_object:
                        continue
                    sync_objects[x.oid.full_oid] = {}
                    sync_objects[x.oid.full_oid]['last_used'] = x.last_used
                    sync_objects[x.oid.full_oid]['last_modified'] = x.last_modified
                    sync_objects[x.oid.full_oid]['object_config'] = x.object_config.copy()
                message = sync_objects
                msg = ("Sending %s objects to peer: %s"
                        % (len(sync_objects), self.peer.name))
                logger.info(msg)

        elif command == "write":
            status = True
            message = None
            try:
                object_id = command_args['object_id']
            except:
                message = "Missing object ID."
                status = False
            try:
                object_config = command_args['object_config']
            except:
                message = "Missing object config."
                status = False
            try:
                last_used = command_args['last_used']
            except:
                last_used = None
            if status:
                object_id = oid.get(object_id)
                object_checksum = object_config['CHECKSUM']
                current_checksum = backend.get_checksum(object_id)
                if current_checksum == object_checksum:
                    status = True
                    message = "done"
                else:
                    msg = "Writing object: %s (%s)" % (object_id, object_checksum)
                    logger.debug(msg)
                    if last_used is not None:
                        object_uuid = object_config['UUID']
                        if last_used is not None:
                            backend.set_last_used(object_id.realm,
                                                object_id.site,
                                                object_id.object_type,
                                                object_uuid, last_used)
                    try:
                        backend.write_config(object_id=object_id,
                                            cluster=False,
                                            index_auto_update=True,
                                            #full_data_update=True,
                                            object_config=object_config)
                        status = True
                        message = "done"
                    except Exception as e:
                        message = "Failed to write object: %s: %s" % (object_id, e)
                        logger.warning(message)

                    # Update signers cache.
                    if object_id.object_type == "user":
                        #new_object = backend.get_object(object_id)
                        # Load instance.
                        try:
                            new_object = backend.get_instance_from_oid(object_id,
                                                                    object_config)
                        except Exception as e:
                            msg = "Failed to load new object: %s: %s" % (object_id, e)
                            self.logger.critical(msg)
                            new_object = None

                        if new_object and new_object.public_key:
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

        elif command == "rename":
            status = True
            message = None
            try:
                object_id = command_args['object_id']
            except:
                message = "Missing object ID."
                status = False
            try:
                new_object_id = command_args['new_object_id']
            except:
                message = "Missing new object ID."
                status = False
            if status:
                msg = "Renaming object: %s: %s" % (object_id, new_object_id)
                logger.debug(msg)
                object_id = oid.get(object_id)
                new_object_id = oid.get(new_object_id)
                try:
                    backend.rename_object(object_id,
                                        new_object_id,
                                        cluster=False)
                    status = True
                    message = "done"
                except Exception as e:
                    message = "Failed to rename object: %s: %s" % (object_id, e)
                    logger.warning(message)

        elif command == "delete":
            status = True
            message = "done"
            try:
                object_uuid = command_args['object_uuid']
            except:
                message = "Missing object UUID."
                status = False
            if status:
                try:
                    object_id = backend.get_oid(object_uuid, instance=True)
                except Exception as e:
                    status = False
            if status and object_id:
                if object_id.object_type == "user":
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
                msg = "Removing object: %s" % object_id
                logger.debug(msg)
                try:
                    backend.delete_object(object_id=object_id)
                    status = True
                    message = "done"
                except UnknownObject:
                    status = True
                    message = "Unknown object."
                except Exception as e:
                    message = "Failed to delete object: %s: %s" % (object_id, e)
                    logger.warning(message)

        elif command == "acquire_lock":
            status = True
            message = "done"
            try:
                lock_type = command_args['lock_type']
            except:
                message = "Missing lock type."
                status = False
            try:
                lock_id = command_args['lock_id']
            except:
                message = "Missing lock ID."
                status = False
            try:
                write = command_args['write']
            except:
                message = "Missing write lock flag."
                status = False
            if status:
                try:
                    lock = locking.acquire_lock(lock_type=lock_type,
                                                lock_id=lock_id,
                                                write=write,
                                                timeout=0)
                    multiprocessing.cluster_locks[lock_id] = lock
                except LockWaitTimeout:
                    status = False
                    message = "Failed to acquire lock."

        elif command == "release_lock":
            status = True
            message = "done"
            try:
                lock_id = command_args['lock_id']
            except:
                message = "Missing lock ID."
                status = False
            if status:
                try:
                    lock = multiprocessing.cluster_locks.pop(lock_id)
                except KeyError:
                    status = False
                    message = "Unknown lock."
                if status:
                    lock.release_lock()

        elif command == "deconfigure_floating_ip":
            status = True
            message = "Floating IP deconfigured."
            msg = "Received request to deconfigure floating IP."
            logger.info(msg)
            try:
                self.comm_handler.send("controld", command="deconfigure_floating_ip")
            except Exception as e:
                status = False
                message = "Failed to send deconfigure floating IP request."
                msg = "Failed to send deconfigure floating IP request: %s" % e
                logger.critical(msg)

        elif command == "start_master_failover":
            missing_nodes = []
            member_nodes = multiprocessing.member_nodes.keys()
            online_nodes = multiprocessing.online_nodes.keys()
            for node_name in online_nodes:
                if node_name in member_nodes:
                    continue
                missing_nodes.append(node_name)
            if missing_nodes:
                status = False
                missing_nodes = " ".join(missing_nodes)
                message = ("Waiting for node(s) to join cluster: %s"
                            % missing_nodes)
            else:
                running_jobs = self.get_running_jobs()
                if running_jobs:
                    status = False
                    message = "Cannot do master failover because of running jobs"
                    message = "%s\n%s" % (message, running_jobs)
                else:
                    status = True
                    message = "Master failover started."
                    config.master_failover = True
                    time.sleep(3)
                    running_jobs = self.get_running_jobs()
                    if running_jobs:
                        status = False
                        config.master_failover = False
                        message = "Cannot do master failover because of running jobs"
                        message = "%s\n%s" % (message, running_jobs)

        elif command == "set_master_failover":
            status = True
            message = "Master failover started successful."
            config.cluster_status = False

        elif command == "get_master_failover_status":
            message = "Master failover status."
            status = config.master_failover

        elif command == "do_nsscache_sync":
            from otpme.lib.classes.command_handler import CommandHandler
            # Get command handler.
            command_handler = CommandHandler(interactive=False)
            # Add sync sites command to queue.
            try:
                command_handler.start_sync(sync_type="nsscache")
                status = True
                message = "Nsscache sync queued."
            except Exception as e:
                message = (_("Error queueing sync nsscache command: %s") % e)
                logger.warning(message)
                status = True

        elif command == "do_radius_reload":
            try:
                freeradius_reload()
                status = True
                message = "Radius reload done."
            except Exception as e:
                message = "Radius reload failed: %s" % e
                status = False

        elif command == "do_master_failover":
            status = True
            message = "Master failover request successful."
            if config.master_failover:
                status = False
                message = "Ongoing master_failover."
            if status:
                msg = "Starting master failover..."
                logger.info(msg)
                config.master_failover = True
                config.cluster_status = False
                result = backend.search(object_type="node",
                                        attribute="uuid",
                                        value="*",
                                        realm=config.realm,
                                        site=config.site,
                                        return_type="instance")
                for x_node in result:
                    if not x_node.enabled:
                        continue
                    if x_node.name == config.host_data['name']:
                        continue
                    try:
                        socket_uri = stuff.get_daemon_socket("clusterd", x_node.name)
                    except Exception as e:
                        msg = "Failed to get clusterd socket: %s: %s" % (x_node.name, e)
                        logger.critical(msg)
                        continue
                    try:
                        clusterd_conn = connections.get("clusterd", socket_uri=socket_uri)
                    except Exception as e:
                        msg = "Cluster connection failed: %s: %s" % (x_node.name, e)
                        logger.critical(msg)
                        continue
                    try:
                        clusterd_conn.set_master_failover()
                    except Exception as e:
                        msg = "Setting master failover status failed: %s: %s" % (x_node.name, e)
                        logger.critical(msg)
                    finally:
                        clusterd_conn.close()

            # Do final sync.
            if status:
                from otpme.lib.classes.command_handler import CommandHandler
                # Sync data objects and sessions.
                master_node = multiprocessing.master_node['master']
                try:
                    socket_uri = stuff.get_daemon_socket("clusterd", master_node)
                except Exception as e:
                    msg = "Failed to get clusterd socket: %s: %s" % (x_node.name, e)
                    logger.critical(msg)
                    socket_uri = None
                clusterd_conn = None
                if socket_uri:
                    try:
                        clusterd_conn = connections.get("clusterd", socket_uri=socket_uri)
                    except Exception as e:
                        msg = "Cluster sync connection failed: %s: %s" % (x_node.name, e)
                        logger.critical(msg)
                if clusterd_conn:
                    msg = "Starting sync of data objects..."
                    logger.info(msg)
                    try:
                        clusterd_conn.sync()
                    except Exception as e:
                        msg = "Master failover sync failed: %s: %s" % (x_node.name, e)
                        logger.critical(msg)
                    finally:
                        clusterd_conn.close()
                command_handler = CommandHandler()
                while True:
                    try:
                        socket_uri = stuff.get_daemon_socket("syncd", master_node)
                    except Exception as e:
                        msg = "Failed to get syncd socket: %s" % e
                        self.logger.warning(msg)
                        time.sleep(1)
                        continue
                    try:
                        sync_status = command_handler.do_sync(sync_type="objects",
                                                            skip_object_deletion=True,
                                                            socket_uri=socket_uri,
                                                            realm=config.realm,
                                                            site=config.site,
                                                            max_tries=3)
                    except Exception as e:
                        msg = "Final sync of objects failed: %s" % e
                        logger.warning(msg)
                        sync_status = False
                    if sync_status is not False:
                        status = True
                        break

            if status:
                while True:
                    config.touch_node_sync_file()
                    new_master_vote = calc_node_vote()
                    multiprocessing.node_votes[config.host_data['name']] = new_master_vote
                    try:
                        master_node = multiprocessing.master_node['master']
                    except:
                        time.sleep(0.01)
                        continue
                    if master_node != self.host_name:
                        logger.info("Waiting for node to get master node...")
                        time.sleep(1)
                        continue
                    break

        response = self.build_response(status, message, encrypt=False)
        return response

    def _close(self):
        pass
