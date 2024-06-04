# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time
import ujson
import signal
import datetime
from prettytable import NONE
from prettytable import FRAME
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
from otpme.lib import filetools
from otpme.lib import connections
from otpme.lib import multiprocessing
from otpme.lib.protocols import status_codes
from otpme.lib.daemon.clusterd import calc_node_vote
from otpme.lib.classes.object_config import ObjectConfig
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
        self.encrypt_session = True
        self.require_master_node = False
        self.require_cluster_status = False
        self.compresss_response = False
        # Call parent class init.
        OTPmeServer1.__init__(self, **kwargs)

    def signal_handler(self, _signal, frame):
        """ Handle signals """
        if _signal != 15:
            return
        for lock in multiprocessing.cluster_write_locks:
            lock.release_lock()
        for lock in multiprocessing.cluster_read_locks:
            lock.release_lock()
        OTPmeServer1.signal_handler(self, _signal, frame)

    def _pre_init(self, *args, **kwargs):
        """ Init protocol handler. """
        # Our PID.
        self.pid = os.getpid()
        # Do atfork stuff.
        multiprocessing.atfork(quiet=True)
        signal.signal(signal.SIGTERM, self.signal_handler)
        signal.signal(signal.SIGINT, self.signal_handler)

    def get_running_jobs(self):
        running_jobs = dict(multiprocessing.running_jobs)
        if len(running_jobs) == 0:
            return
        table_headers = ['Start Time', 'Job Name', 'Auth Token', 'PID']
        table = PrettyTable(table_headers,
                            header_style="title",
                            vrules=NONE,
                            hrules=FRAME)
        job_added = False
        table.align = "l"
        table.padding_width = 0
        table.right_padding_width = 1
        for x in running_jobs:
            x_name = running_jobs[x]['name']
            x_pid = running_jobs[x]['pid']
            if x_pid:
                if not stuff.check_pid(x_pid):
                    continue
            x_start_time = running_jobs[x]['start_time']
            x_start_time = datetime.datetime.fromtimestamp(x_start_time)
            try:
                x_auth_token = running_jobs[x]['auth_token']
            except KeyError:
                x_auth_token = None
            row = [x_start_time, x_name, x_auth_token, x_pid]
            table.add_row(row)
            job_added = True
        if not job_added:
            return
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
                            "object_exists",
                            "get_node_vote",
                            "set_node_sync",
                            "unset_node_sync",
                            "set_node_online",
                            "get_master_node",
                            "do_radius_reload",
                            "do_nsscache_sync",
                            "do_daemon_reload",
                            "get_member_nodes",
                            "get_data_revision",
                            "do_master_failover",
                            "get_cluster_quorum",
                            "get_cluster_status",
                            "set_master_failover",
                            "get_node_sync_status",
                            "start_master_failover",
                            "get_master_sync_status",
                            "deconfigure_floating_ip",
                            "get_master_failover_status",
                        ]

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

        # Check if we got a valid command
        if not command in valid_commands:
            msg = ("Received unknown command %s from client: %s"
                    % (command, self.client))
            logger.warning(msg)
            message = "Unknown command: %s" % command
            status = False

        elif command == "ping":
            message = "pong"
            status = True
            msg = "Received ping."
            logger.debug(msg)

        elif command == "get_data_revision":
            status = True
            message = config.get_data_revision()

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
            if not config.master_failover:
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
                message = calc_node_vote()

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
                return_attributes = ['oid', 'sync_checksum']
                result = backend.search(object_types=object_types,
                                        attribute="uuid",
                                        value="*",
                                        return_attributes=return_attributes)
                sync_objects = {}
                sync_objects_count = 0
                for x_uuid in result:
                    x_oid = result[x_uuid]['oid']
                    x_checksum = result[x_uuid]['sync_checksum']
                    sync_object = False
                    try:
                        remote_object_data = remote_objects[x_oid.full_oid]
                    except KeyError:
                        remote_object_data = None
                        sync_object = True
                    if remote_object_data:
                        remote_checksum = remote_object_data['sync_checksum']
                        if remote_checksum != x_checksum:
                            sync_object = True
                    if not sync_object:
                        sync_objects[x_oid.full_oid] = None
                        continue
                    x_object_config = backend.read_config(x_oid)
                    if not x_object_config:
                        continue
                    x_object_config = x_object_config.copy()
                    x_sync_checksum = backend.get_sync_checksum(x_oid)
                    x_object_config['SYNC_CHECKSUM'] = x_sync_checksum
                    x_last_used = backend.get_last_used(x_oid.realm,
                                                        x_oid.site,
                                                        x_oid.object_type,
                                                        x_uuid)
                    sync_objects_count += 1
                    sync_objects[x_oid.full_oid] = {}
                    sync_objects[x_oid.full_oid]['last_used'] = x_last_used
                    sync_objects[x_oid.full_oid]['object_config'] = x_object_config
                message = sync_objects
                msg = ("Sending %s objects to peer: %s"
                        % (sync_objects_count, self.peer.name))
                logger.info(msg)

        elif command == "object_exists":
            status = True
            message = None
            try:
                object_id = command_args['object_id']
            except:
                message = "Missing object ID."
                status = False
            if status:
                object_id = oid.get(object_id)
                message = backend.object_exists(object_id)

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
                index_journal = command_args['index_journal']
            except:
                message = "Missing index journal."
                status = False
            try:
                last_used = command_args['last_used']
            except:
                last_used = None
            try:
                full_data_update = command_args['full_data_update']
            except:
                full_data_update = False
            try:
                full_index_update = command_args['full_index_update']
            except:
                full_index_update = False
            if config.daemon_shutdown:
                message = "Daemon shutdown."
                status = False
            if status:
                object_checksum = object_config['CHECKSUM']
                msg = ("Writing object: %s (%s)" % (object_id, object_checksum))
                logger.debug(msg)
                message = "done"
                while True:
                    entry_time = str(time.time_ns())
                    cluster_journal_file = os.path.join(config.cluster_in_journal_dir, entry_time)
                    if os.path.exists(cluster_journal_file):
                        continue
                    break
                object_config = ObjectConfig(object_id, object_config, encrypted=False)
                object_config = object_config.encrypt(config.master_key,
                                                    update_checksums=False)
                object_data = {
                                'action'            : 'write',
                                'object_id'         : object_id,
                                'last_used'         : last_used,
                                'object_config'     : object_config,
                                'index_journal'     : index_journal,
                                'full_data_update'  : full_data_update,
                                'full_index_update' : full_index_update,
                            }
                file_content = ujson.dumps(object_data)
                try:
                    filetools.create_file(path=cluster_journal_file,
                                            content=file_content,
                                            compression="lz4")
                except Exception as e:
                    message = ("Failed to write cluster journal: %s: %s: %s"
                                % (object_id, cluster_journal_file, e))
                    status = False
                else:
                    multiprocessing.cluster_in_event.set()
                    message = "done"

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
            if config.daemon_shutdown:
                message = "Daemon shutdown."
                status = False
            if status:
                while True:
                    entry_time = str(time.time_ns())
                    cluster_journal_file = os.path.join(config.cluster_in_journal_dir, entry_time)
                    if os.path.exists(cluster_journal_file):
                        continue
                    break
                object_data = {
                                'action'            : 'rename',
                                'object_id'         : object_id,
                                'new_object_id'     : new_object_id,
                            }
                file_content = ujson.dumps(object_data)
                try:
                    filetools.create_file(path=cluster_journal_file,
                                            content=file_content,
                                            compression="lz4")
                except Exception as e:
                    message = ("Failed to write cluster journal: %s: %s: %s"
                                % (object_id, cluster_journal_file, e))
                    status = False
                else:
                    multiprocessing.cluster_in_event.set()
                    message = "done"

        elif command == "delete":
            status = True
            message = "done"
            try:
                object_id = command_args['object_id']
            except:
                message = "Missing object UUID."
                status = False
            if config.daemon_shutdown:
                message = "Daemon shutdown."
                status = False
            if status:
                while True:
                    entry_time = str(time.time_ns())
                    cluster_journal_file = os.path.join(config.cluster_in_journal_dir, entry_time)
                    if os.path.exists(cluster_journal_file):
                        continue
                    break
                object_data = {
                                'action'        : 'delete',
                                'object_id'     : object_id,
                            }
                file_content = ujson.dumps(object_data)
                try:
                    filetools.create_file(path=cluster_journal_file,
                                            content=file_content,
                                            compression="lz4")
                except Exception as e:
                    message = ("Failed to write cluster journal: %s: %s: %s"
                                % (object_id, cluster_journal_file, e))
                    status = False
                else:
                    multiprocessing.cluster_in_event.set()
                    message = "done"

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
            if write:
                if lock_id in multiprocessing.cluster_write_locks:
                    status = False
                    message = "Write lock exits: %s" % lock_id
            else:
                if lock_id in multiprocessing.cluster_read_locks:
                    status = False
                    message = "Read lock exits: %s" % lock_id
            if status:
                try:
                    lock = locking.acquire_lock(lock_type=lock_type,
                                                lock_id=lock_id,
                                                write=write,
                                                timeout=0)
                except LockWaitTimeout:
                    status = False
                    message = "Failed to acquire lock."
                else:
                    if write:
                        multiprocessing.cluster_write_locks[lock_id] = lock
                    else:
                        multiprocessing.cluster_read_locks[lock_id] = lock

        elif command == "release_lock":
            status = True
            message = "done"
            try:
                lock_id = command_args['lock_id']
            except:
                message = "Missing lock ID."
                status = False
            try:
                write = command_args['write']
            except:
                message = "Missing lock ID."
                status = False
            if status:
                if write:
                    try:
                        lock = multiprocessing.cluster_write_locks.pop(lock_id)
                    except KeyError:
                        status = False
                        message = "Unknown write lock: %s" % lock_id
                else:
                    try:
                        lock = multiprocessing.cluster_read_locks.pop(lock_id)
                    except KeyError:
                        status = False
                        message = "Unknown read lock: %s" % lock_id
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
            config.master_failover = True

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
            else:
                msg = "nsscache sync started."
                logger.info(msg)

        elif command == "do_radius_reload":
            try:
                freeradius_reload()
                status = True
                message = "Radius reload done."
            except Exception as e:
                message = "Radius reload failed: %s" % e
                status = False
            else:
                msg = "Freeradius reloaded."
                logger.info(msg)

        elif command == "do_daemon_reload":
            # Reload after adding new CRL.
            self._send_daemon_msg(daemon="controld",
                                    command="reload",
                                    timeout=1)
            status = True
            message = "Daemonreload queued."

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
                try:
                    master_node = multiprocessing.master_node['master']
                except KeyError:
                    status = False
                    message = "No master node elected."
                if status:
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
                    #new_master_vote = calc_node_vote()
                    #multiprocessing.node_votes[config.host_data['name']] = new_master_vote
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
