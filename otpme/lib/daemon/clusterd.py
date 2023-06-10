# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
# Distributed under the terms of the GNU General Public License v2
import os
import time
import json
import glob
import shutil
import random
import signal
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
from otpme.lib import filetools
from otpme.lib import connections
from otpme.lib import multiprocessing
from otpme.lib.protocols import status_codes
from otpme.lib.daemon.otpme_daemon import OTPmeDaemon
from otpme.lib.classes.object_config import ObjectConfig
from otpme.lib.freeradius import reload as freeradius_reload

from otpme.lib.exceptions import *

LOCK_TYPE = "cluster_journal"

node_checksums = []
processed_events = []
processed_journal_entries = []
last_node_check = time.time()
default_callback = config.get_callback()

REGISTER_BEFORE = ['otpme.lib.daemon.controld']
REGISTER_AFTER = []

CLUSTER_JOURNAL_NAME = "cluster_journal"
CLUSTER_JOURNAL_DIR = os.path.join(config.spool_dir, CLUSTER_JOURNAL_NAME)

def register():
    """ Register OTPme daemon. """
    config.register_otpme_daemon("clusterd")
    multiprocessing.register_shared_dict("node_votes")
    multiprocessing.register_shared_dict("sync_nodes")
    multiprocessing.register_shared_dict("master_node")
    multiprocessing.register_shared_dict("enabled_nodes")
    multiprocessing.register_shared_dict("online_nodes")
    multiprocessing.register_shared_dict("member_nodes")
    multiprocessing.register_shared_dict("running_jobs")
    multiprocessing.register_shared_dict("cluster_quorum")
    multiprocessing.register_shared_list("init_sync_done")
    multiprocessing.register_shared_list("master_sync_done")
    multiprocessing.register_shared_list("init_sync_running")
    multiprocessing.register_shared_dict("radius_reload_queue")
    multiprocessing.register_shared_dict("nsscache_sync_queue")
    register_cluster_journal()

def register_cluster_journal():
    """ Directory to store cluster cluster journal. """
    locking.register_lock_type(LOCK_TYPE, module=__file__)
    config.register_config_var("cluster_journal_dir", str, CLUSTER_JOURNAL_DIR)
    backend.register_data_dir(name=CLUSTER_JOURNAL_NAME,
                            path=CLUSTER_JOURNAL_DIR,
                            drop=True,
                            perms=0o770)

def check_cluster_status():
    if not config.cluster_status:
        msg = "Cluster not ready."
        raise OTPmeException(msg)
    if config.master_failover:
        msg = "Ongoing master failover."
        raise OTPmeException(msg)

def cluster_nsscache_sync():
    if config.use_api:
        return
    if config.one_node_setup:
        return
    multiprocessing.nsscache_sync_queue.clear()
    sync_time = time.time()
    try:
        multiprocessing.nsscache_sync_queue[sync_time] = []
    except ValueError:
        pass
    multiprocessing.cluster_event.set()

def cluster_radius_reload():
    if config.use_api:
        return
    try:
        freeradius_reload()
        msg = "Radius reload successful."
        config.logger.info(msg)
    except Exception as e:
        msg = "Failed to reload radius: %s" % e
        config.logger.critical(msg)
    if config.one_node_setup:
        return
    multiprocessing.radius_reload_queue.clear()
    reload_time = time.time() + 5
    try:
        multiprocessing.radius_reload_queue[reload_time] = []
    except ValueError:
        pass
    multiprocessing.cluster_event.set()

def cluster_sync_object(object_uuid, object_id, action, object_config=None,
    new_object_id=None, last_modified=None, checksum=None, wait_for_write=True):
    if config.one_node_setup:
        return
    if multiprocessing.cluster_event is None:
        return
    if config.two_node_setup:
        if len(multiprocessing.online_nodes) == 0:
            return
    cluster_journal_entry = ClusterJournalEntry(timestamp=time.time(),
                                            action=action,
                                            object_uuid=object_uuid,
                                            object_id=object_id,
                                            checksum=checksum,
                                            object_config=object_config,
                                            new_object_id=new_object_id,
                                            last_modified=last_modified)
    try:
        cluster_journal_entry.add()
    except Exception as e:
        msg = ("Failed to add cluster journal entry: %s: %s"
                % (object_id, e))
        config.logger.critical(msg)
        #print(msg)
        return
    multiprocessing.cluster_event.set()
    if wait_for_write:
        if config.debug_level() > 2:
            msg = ("Waiting for cluster data write: %s %s %s"
                    % (config.daemon_name, action, object_id))
            config.logger.debug(msg)
        object_event_name = "/%s" % cluster_journal_entry.timestamp
        object_event = multiprocessing.Event(object_event_name)
        object_event.wait()
        if config.debug_level() > 2:
            msg = ("Finished cluster data write: %s %s %s"
                    % (config.daemon_name, action, object_id))
            config.logger.debug(msg)

def calc_node_vote():
    if not os.path.exists(config.node_sync_file):
        node_vote = random.random()
        return node_vote
    #newest_object = stuff.get_newest_object()
    #node_vote = newest_object['last_modified']
    node_vote = os.path.getmtime(config.node_sync_file)
    return node_vote

class ClusterJournalEntry(object):
    def __init__(self, timestamp, object_uuid=None, action=None,
        object_id=None, checksum=None, object_config=None,
        new_object_id=None, last_modified=None):
        self.timestamp = timestamp
        self.action = action
        self.object_id = object_id
        self.object_uuid = object_uuid
        self.object_checksum = checksum
        self.new_object_id = new_object_id
        self.object_config = object_config
        self.last_modified = last_modified
        self.entry_dir = os.path.join(config.cluster_journal_dir,
                                    str(self.timestamp))
        self.nodes_dir = os.path.join(self.entry_dir, "nodes")
        self.logger = config.logger

    def __str__(self):
        return self.object_uuid

    def __repr__(self):
        # We need a string when object is used as dict key!
        return self.__str__()

    def __hash__(self):
        return hash(self.__str__())

    def __eq__(self, other):
        return self.object_uuid == other.object_uuid

    def __ne__(self, other):
        return self.object_uuid != other.object_uuid

    def __lt__(self, other):
        return self.__str__() < other.__str__()

    def __gt__(self, other):
        return self.__str__() > other.__str__()

    def get_journal_file(self):
        _file = os.path.join(self.entry_dir, "data.json")
        return _file

    def lock(self):
        self._lock = locking.acquire_lock(lock_type=LOCK_TYPE,
                                        lock_id=self.timestamp)
    def release(self):
        if not self._lock:
            return
        self._lock.release_lock()

    def load(self):
        journal_file = self.get_journal_file()
        self.lock()
        if not os.path.exists(journal_file):
            self.release()
            msg = "Cluster journal entry not found."
            raise NotFound(msg)
        try:
            file_content = filetools.read_file(path=journal_file)
        finally:
            self.release()
        object_data = json.loads(file_content)
        self.action = object_data['action']
        self.object_id = object_data['object_id']
        self.timestamp = object_data['time']
        self.object_uuid = object_data['uuid']
        self.object_checksum = object_data['checksum']
        self.new_object_id = object_data['new_object_id']
        self.last_modified = object_data['last_modified']
        object_config = object_data['object_config']
        # Load object data.
        if not object_config:
            return
        object_config = ObjectConfig(object_id=self.object_id,
                                    object_config=object_config,
                                    encrypted=True)
        object_config = object_config.decrypt(config.master_key)
        self.object_config = object_config.copy()

    def add(self):
        journal_file = self.get_journal_file()
        if os.path.exists(journal_file):
            msg = "Cluster data entry already exists: %s" % self.timestamp
            raise OTPmeException(msg)
        object_id = self.object_id
        object_uuid = self.object_uuid
        object_config = self.object_config
        new_object_id = self.new_object_id
        object_checksum = self.object_checksum
        last_modified = self.last_modified
        timestamp = self.timestamp
        if object_id.full_oid is None:
            object_id = oid.get(object_id.read_oid, resolve=True)
        if timestamp is None:
            timestamp = time.time()
        if object_config:
            object_config = ObjectConfig(object_id=object_id,
                                        object_config=object_config,
                                        encrypted=False)
            object_config = object_config.encrypt(config.master_key)
            object_config = object_config.copy()
        object_data = {}
        object_data['time'] = timestamp
        object_data['uuid'] = object_uuid
        object_data['action'] = self.action
        object_data['checksum'] = object_checksum
        object_data['object_id'] = object_id.full_oid
        object_data['new_object_id'] = new_object_id
        object_data['object_config'] = object_config
        object_data['last_modified'] = last_modified
        self.lock()
        try:
            filetools.create_dir(self.entry_dir)
            file_content = json.dumps(object_data, sort_keys=True)
            filetools.create_file(path=journal_file, content=file_content)
        finally:
            self.release()

    def add_node(self, node_name):
        self.lock()
        try:
            node_file = os.path.join(self.nodes_dir, node_name)
            try:
                filetools.create_dir(self.nodes_dir)
            except FileExistsError:
                pass
            fd = open(node_file, "w")
            fd.close()
        finally:
            self.release()

    def get_nodes(self):
        self.lock()
        nodes = []
        for node_file in sorted(glob.glob(self.nodes_dir + "/*")):
            node_name = os.path.basename(node_file)
            nodes.append(node_name)
        self.release()
        return nodes

    def delete(self):
        self.lock()
        msg = ("Deleting cluster journal entry: %s" % self.object_id)
        self.logger.debug(msg)
        try:
            shutil.rmtree(self.entry_dir)
        except FileNotFoundError:
            pass
        except Exception as e:
            msg = "Failed to remove cluster journal entry: %s" % e
            self.logger.warning(msg)
        finally:
            self.release()

class ClusterDaemon(OTPmeDaemon):
    """ ClusterDaemon. """
    def __init__(self, *args, **kwargs):
        self.node_conn = None
        self.member_candidate = False
        self.cluster_connections = {}
        self.cluster_comm_child = None
        self.interprocess_comm_child = None
        super(ClusterDaemon, self).__init__(*args, **kwargs)

    def signal_handler(self, _signal, frame):
        """ Exit on signal. """
        if _signal != 15:
            return
        # Act only on our own PID.
        if os.getpid() != self.pid:
            return
        msg = ("Received SIGTERM.")
        self.logger.debug(msg)
        if config.start_freeradius:
            self.stop_freeradius()
        self.close_childs()
        return super(ClusterDaemon, self).signal_handler(_signal, frame)

    def start_childs(self):
        """ Start child processes childs. """
        msg = "Starting cluster communication..."
        self.logger.info(msg)
        # Interprocess communication.
        self.interprocess_comm_child = multiprocessing.start_process(name=self.name,
                                        target=self.start_interprocess_comm)
        # Start cluster communication.
        self.cluster_comm_child = multiprocessing.start_process(name=self.name,
                                        target=self.start_cluster_communication)

    def close_childs(self):
        """ Stop cluster communication childs. """
        msg = "Stopping cluster communication..."
        self.logger.info(msg)
        if self.interprocess_comm_child:
            try:
                self.interprocess_comm_child.terminate()
                self.interprocess_comm_child.join()
            except Exception as e:
                msg = "Failed to stop cluster IPC child: %s" % e
                self.logger.warning(msg)
            while self.interprocess_comm_child.is_alive():
                time.sleep(0.01)
        if self.cluster_comm_child:
            try:
                self.cluster_comm_child.terminate()
                self.cluster_comm_child.join()
            except Exception as e:
                msg = "Failed to stop cluster communication child: %s" % e
                self.logger.warning(msg)
            while self.cluster_comm_child.is_alive():
                time.sleep(0.01)

    @property
    def host_name(self):
        try:
            host_name = config.host_data['name']
        except:
            return
        return host_name

    @property
    def host_type(self):
        try:
            host_type = config.host_data['type']
        except:
            return
        return host_type

    def get_cluster_journal(self):
        cluster_journal_dirs = sorted(glob.glob(CLUSTER_JOURNAL_DIR + "/*"))
        return cluster_journal_dirs

    def handle_events(self):
        global processed_events
        if len(processed_events) > 102400:
            processed_events = processed_events[51200:]
        for cluster_entry_dir in self.get_cluster_journal():
            if cluster_entry_dir in processed_events:
                continue
            processed_events.append(cluster_entry_dir)
            object_event_name = "/%s" % os.path.basename(cluster_entry_dir)
            object_event = multiprocessing.Event(object_event_name)
            object_event.set()
            object_event.unlink()

    def node_leave(self, node_name):
        self.node_conn = None
        self.calc_quorum()
        try:
            multiprocessing.member_nodes.pop(node_name)
        except KeyError:
            pass
        try:
            multiprocessing.online_nodes.pop(node_name)
        except KeyError:
            pass
        try:
            multiprocessing.init_sync_done.remove(node_name)
        except ValueError:
            pass

    def get_conn_event_name(self, node_name):
        conn_even_name = "/clusterd-main-event-%s" % node_name
        return conn_even_name

    def do_init_sync(self, node_name):
        do_init_sync = False
        if node_name not in list(multiprocessing.init_sync_running):
            if node_name not in list(multiprocessing.init_sync_done):
                do_init_sync = True
        if not do_init_sync:
            return
        # We cannot clear cluster writes here because on node join this
        # will lead to loosing writes of the new node object.
        # Mark as initial sync running.
        multiprocessing.init_sync_running.append(node_name)
        # Start init sync process.
        multiprocessing.start_process(name=self.name,
                                    target=self.start_initial_sync,
                                    target_args=(node_name,),
                                    join=True)

    def start_initial_sync(self, node_name):
        """ Start initial sync of sessions etc.. """
        # Set proctitle.
        new_proctitle = "%s (Initial sync)" % self.full_name
        setproctitle.setproctitle(new_proctitle)

        while True:
            # Get node.
            result = backend.search(object_type="node",
                                    attribute="name",
                                    value=node_name,
                                    realm=config.realm,
                                    site=config.site,
                                    return_type="instance")
            if not result:
                msg = "Unknown node: %s" % node_name
                self.logger.warning(msg)
                try:
                    multiprocessing.init_sync_running.remove(node_name)
                except ValueError:
                    pass
                try:
                    multiprocessing.init_sync_done.remove(node_name)
                except ValueError:
                    pass
                return
            node = result[0]
            # Check for enabled status.
            if not node.enabled:
                break

            try:
                socket_uri = stuff.get_daemon_socket("clusterd", node.name)
            except Exception as e:
                msg = "Failed to get daemon socket: %s" % e
                self.logger.warning(msg)
                time.sleep(1)
                continue
            try:
                clusterd_conn = connections.get("clusterd",
                                                timeout=None,
                                                socket_uri=socket_uri)
            except Exception as e:
                msg = ("Failed to get initial sync connection: %s: %s"
                        % (node_name, e))
                self.logger.warning(msg)
                time.sleep(1)
                continue
            try:
                clusterd_conn.sync()
                break
            except Exception as e:
                msg = "Failed to sync with node: %s: %s" % (node_name, e)
                self.logger.warning(msg)
                time.sleep(1)
            finally:
                clusterd_conn.close()
        if node_name not in multiprocessing.init_sync_done:
            multiprocessing.init_sync_done.append(node_name)
        try:
            multiprocessing.init_sync_running.remove(node_name)
        except ValueError:
            pass

    def start_interprocess_comm(self):
        """ Start cluster interprocess communication. """
        # Set proctitle.
        new_proctitle = "%s (Cluster IPC)" % self.full_name
        setproctitle.setproctitle(new_proctitle)
        def signal_handler(_signal, frame):
            if _signal != 15:
                return
            # Cleanup IPC stuff.
            multiprocessing.cleanup()
            # Finally exit.
            os._exit(0)
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)
        while True:
            multiprocessing.cluster_event.wait()
            multiprocessing.cluster_event.clear()
            for node_name in multiprocessing.enabled_nodes:
                conn_even_name = self.get_conn_event_name(node_name)
                conn_event = multiprocessing.Event(conn_even_name)
                conn_event.set()

    def do_master_node_election(self):
        """ Do master node election. """
        node_fails = {}
        node_vote = calc_node_vote()
        multiprocessing.node_votes[self.host_name] = node_vote

        while True:
            for node_name in multiprocessing.enabled_nodes:
                if node_name == self.host_name:
                    continue
                try:
                    socket_uri = stuff.get_daemon_socket("clusterd", node_name)
                except Exception as e:
                    msg = "Failed to get daemon socket: %s" % e
                    self.logger.warning(msg)
                    try:
                        multiprocessing.node_votes.pop(node_name)
                    except:
                        pass
                    continue
                try:
                    clusterd_conn = connections.get("clusterd",
                                                    timeout=None,
                                                    socket_uri=socket_uri)
                except Exception as e:
                    try:
                        node_fails[node_name] += 1
                    except:
                        node_fails[node_name] = 1
                    msg = ("Failed to get master node election connection: %s: %s"
                            % (node_name, e))
                    self.logger.warning(msg)
                    try:
                        multiprocessing.node_votes.pop(node_name)
                    except:
                        pass
                    time.sleep(1)
                    continue
                try:
                    x_node_vote = clusterd_conn.get_node_vote()
                except Exception as e:
                    msg = ("Failed to get cluster vote: %s: %s"
                            % (node_name, e))
                    self.logger.warning(msg)
                    x_node_vote = None
                if x_node_vote is None:
                    try:
                        multiprocessing.node_votes.pop(node_name)
                    except:
                        pass
                    continue
                if config.debug_level() > 2:
                    msg = ("Got cluster vote from node: %s: %s"
                            % (node_name, x_node_vote))
                    self.logger.debug(msg)
                multiprocessing.node_votes[node_name] = x_node_vote

            conn_tries_done = True
            for x_node in multiprocessing.enabled_nodes:
                if x_node in multiprocessing.node_votes:
                    continue
                try:
                    x_node_fails = node_fails[x_node]
                except:
                    x_node_fails = 0
                if x_node_fails < 3:
                    continue
                conn_tries_done = False

            if not conn_tries_done:
                continue

            node_scores = multiprocessing.node_votes.copy()
            x_sort = lambda x: node_scores[x]
            node_scores_sorted = sorted(node_scores, key=x_sort, reverse=True)
            new_master_node = node_scores_sorted[0]
            #print("_______________________________________", node_scores_sorted)

            try:
                old_master_node = multiprocessing.master_node['master']
            except KeyError:
                old_master_node = None
            if old_master_node != new_master_node:
                self.logger.info("Node votes: %s" % node_scores)

            required_votes = self.calc_quorum()[1]
            if len(node_scores_sorted) >= required_votes:
                return new_master_node
            msg = "Master node election failed: Not enough votes"
            for x in node_scores_sorted:
                msg = "%s: %s" % (msg, x)
            raise MasterNodeElectionFailed(msg)

    def calc_quorum(self):
        """ Calculate cluster quorum. """
        search_attributes = {
                            'uuid'      : {'value':"*"},
                            'enabled'   : {'value':True},
                            }
        enabled_nodes = {}
        result = backend.search(object_type="node",
                            attributes=search_attributes,
                            realm=config.realm,
                            site=config.site,
                            return_type="instance")
        quorum = False
        for node in result:
            enabled_nodes[node.name] = node
        # We need at least half of the enabled nodes to gain quorum.
        required_votes = len(enabled_nodes) / 2
        # Required votes must be +1 if its even.
        if required_votes % 2 == 0:
            required_votes += 1
        #elif required_votes == 1:
        #    required_votes += 1
        # Get current (active) node votes including own node.
        current_votes = 1
        for node_name in multiprocessing.init_sync_done:
            try:
                node = enabled_nodes[node_name]
            except:
                continue

            try:
                socket_uri = stuff.get_daemon_socket("clusterd", node_name)
            except Exception as e:
                msg = "Failed to get daemon socket: %s" % e
                self.logger.warning(msg)

            try:
                clusterd_conn = connections.get("clusterd",
                                                timeout=None,
                                                socket_uri=socket_uri)
            except Exception as e:
                msg = ("Failed to get cluster connection: %s: %s"
                        % (node_name, e))
                self.logger.warning(msg)
                continue

            if not clusterd_conn.get_init_sync_status(self.host_name):
                continue

            current_votes += 1

        if current_votes >= required_votes:
            quorum = True

        # Set global quorum.
        config.cluster_quorum = quorum
        multiprocessing.cluster_quorum['quorum'] = current_votes
        # As soon as we lost quorum the cluster state must change to false.
        if not config.cluster_quorum:
            config.cluster_status = False

        return current_votes, required_votes, quorum

    def handle_node_connections(self):
        """ Handle node connections. """

        search_attributes = {
                            'uuid'      : {'value':"*"},
                            'enabled'   : {'value':True},
                            }
        # Get all enabled nodes.
        result = backend.search(object_type="node",
                            attributes=search_attributes,
                            realm=config.realm,
                            site=config.site,
                            return_type="instance")
        all_nodes = {}
        for node in result:
            all_nodes[node.name] = node

        if len(all_nodes) == 1:
            config.one_node_setup = True
        elif len(all_nodes) == 2:
            config.two_node_setup = True
            config.one_node_setup = False
        else:
            config.two_node_setup = False
            config.one_node_setup = False

        own_node = all_nodes[self.host_name]
        if not own_node.enabled:
            msg = "Node disabled. Closing cluster connections."
            self.logger.warning(msg)
            if self.cluster_connections:
                self.close_cluster_connections()
            return
        # Make sure we have a connection to all nodes.
        for node_name in all_nodes:
            try:
                node = all_nodes[node_name]
            except KeyError:
                continue
            if not node.enabled:
                continue
            if node.name == self.host_name:
                continue
            try:
                cluster_proc = self.cluster_connections[node_name]
            except:
                continue
            if cluster_proc.is_alive():
                continue
            cluster_proc.join()
            try:
                self.cluster_connections.pop(node_name)
            except KeyError:
                pass
            try:
                multiprocessing.enabled_nodes.pop(node_name)
            except KeyError:
                pass

        for node_name in all_nodes:
            try:
                node = all_nodes[node_name]
            except KeyError:
                continue
            if not node.enabled:
                continue
            if node.name == self.host_name:
                continue
            if node.name in self.cluster_connections:
                continue
            # Start node connection process.
            cluster_proc = multiprocessing.start_process(name=self.name,
                                        target=self.start_cluster_connection,
                                        target_args=(node.name,))
            self.cluster_connections[node.name] = cluster_proc
            multiprocessing.enabled_nodes[node.name] = True
        # Remove connection to e.g. disabled nodes.
        for node_name in dict(self.cluster_connections):
            try:
                node = all_nodes[node_name]
            except KeyError:
                node = None
            if node and node.enabled:
                continue
            cluster_proc = self.cluster_connections[node_name]
            cluster_proc.terminate()
            cluster_proc.join()
            self.cluster_connections.pop(node_name)
            self.node_leave(node_name)
            try:
                multiprocessing.enabled_nodes.pop(node_name)
            except KeyError:
                pass
            try:
                multiprocessing.node_votes.pop(node_name)
            except KeyError:
                pass
        # Remove nodes not active anymore (e.g. deleted).
        for node_name in multiprocessing.enabled_nodes:
            if node_name in self.cluster_connections:
                continue
            self.node_leave(node_name)
            try:
                multiprocessing.enabled_nodes.pop(node_name)
            except KeyError:
                pass
            try:
                multiprocessing.node_votes.pop(node_name)
            except KeyError:
                pass

    def switch_master_node(self, current_master_node, new_master_node):
        """ Switch master node. """
        msg = ("Master node elected: %s" % new_master_node)
        self.logger.info(msg)
        multiprocessing.master_node['master'] = new_master_node
        if new_master_node == self.host_name:
            msg = "Sending request to configure floating IP."
            self.logger.info(msg)
            self.comm_handler.send("controld", command="configure_floating_ip")
        elif current_master_node == self.host_name:
            msg = "Sending request to deconfigure floating IP."
            self.logger.info(msg)
            self.comm_handler.send("controld", command="deconfigure_floating_ip")

        if new_master_node == self.host_name:
            if self.host_name not in multiprocessing.master_sync_done:
                multiprocessing.master_sync_done.append(self.host_name)
            return

        if current_master_node is not None:
            if self.host_name not in multiprocessing.master_sync_done:
                multiprocessing.master_sync_done.append(self.host_name)
            return

        self.wait_for_master_node_failover(new_master_node)
        self.do_master_node_sync(new_master_node)

    def wait_for_master_node_failover(self, master_node):
        """ Wait for master node to finish failover. """
        # Get new master node socket.
        try:
            socket_uri = stuff.get_daemon_socket("clusterd", master_node)
        except Exception as e:
            msg = "Failed to get clusterd socket: %s" % e
            self.logger.warning(msg)
            return
        # Wait for master node to finish failover.
        max_tries = 3
        current_try = 0
        while True:
            try:
                clusterd_conn = connections.get("clusterd",
                                                timeout=None,
                                                socket_uri=socket_uri)
            except Exception as e:
                msg = ("Failed to get cluster connection: %s: %s"
                        % (master_node, e))
                self.logger.warning(msg)
                current_try += 1
                if current_try >= max_tries:
                    msg = ("Failed to get cluster connection after %s tries."
                            % max_tries)
                    self.logger.warning(msg)
                    return
                time.sleep(1)
                continue
            master_failover_status = clusterd_conn.get_master_failover_status()
            if not master_failover_status:
                break
            time.sleep(1)

    def do_node_check(self, node_name):
        global last_node_check
        if node_name in multiprocessing.member_nodes:
            return True
        node_last_checked_time = time.time() - last_node_check
        if node_last_checked_time < 1:
            return False
        last_node_check = time.time()

        if self.node_conn is None:
            try:
                socket_uri = stuff.get_daemon_socket("clusterd", node_name)
            except Exception as e:
                msg = ("Failed to get clusterd daemon socket: %s: %s"
                        % (node_name, e))
                self.logger.warning(msg)
                try:
                    multiprocessing.init_sync_done.remove(node_name)
                except ValueError:
                    pass
                return False

            #print("get cluster conn", node_name)
            try:
                self.node_conn = connections.get("clusterd",
                                                timeout=None,
                                                socket_uri=socket_uri)
                multiprocessing.online_nodes[node_name] = True
            except Exception as e:
                msg = ("Failed to get cluster connection: %s: %s"
                        % (node_name, e))
                self.logger.warning(msg)
                self.node_leave(node_name)
                return False

        # Mark node as online.
        try:
            self.node_conn.set_node_online()
        except Exception as e:
            msg = ("Failed to set node online status: %s: %s"
                    % (node_name, e))
            self.logger.warning(msg)
            raise OTPmeException(msg)

        try:
            self.do_init_sync(node_name)
        except Exception as e:
            msg = "Failed to start initial sync: %s" % e
            self.logger.critical(msg)
            try:
                multiprocessing.init_sync_done.remove(node_name)
            except ValueError:
                pass
            try:
                multiprocessing.init_sync_running.remove(node_name)
            except ValueError:
                pass
            return False

        try:
            current_master_node = multiprocessing.master_node['master']
        except:
            msg = "Waiting for master node election..."
            self.logger.info(msg)
            return False

        if node_name not in list(multiprocessing.init_sync_done):
            msg = "Waiting for initial sync with node to finish: %s" % node_name
            #print(msg)
            self.logger.info(msg)
            return False

        try:
            if not self.node_conn.get_init_sync_status(self.host_name):
                msg = "Waiting for node to finish initial sync: %s" % node_name
                #print(msg)
                self.logger.info(msg)
                return False
        except Exception as e:
            msg = "Failed to get node sync status: %s: %s" % (node_name, e)
            self.logger.critical(msg)
            self.node_leave(node_name)
            return False

        if current_master_node != node_name:
            try:
                if not self.node_conn.get_master_sync_status():
                    msg = "Waiting for node to finish master sync: %s" % node_name
                    #print(msg)
                    self.logger.info(msg)
                    return False
            except Exception as e:
                msg = "Failed to get master sync status: %s: %s" % (node_name, e)
                self.logger.critical(msg)
                self.node_leave(node_name)

        # Node joined the cluster.
        self.member_candidate = True

        return True

    def do_master_node_sync(self, master_node):
        """ Start initial sync with master node. """
        from otpme.lib.classes.command_handler import CommandHandler
        try:
            socket_uri = stuff.get_daemon_socket("syncd", master_node)
        except Exception as e:
            msg = "Failed to get syncd socket: %s" % e
            self.logger.warning(msg)
            return

        msg = "Starting initial sync with master node..."
        self.logger.info(msg)
        max_tries = 3
        current_try = 0
        command_handler = CommandHandler()
        while True:
            try:
                sync_status = command_handler.do_sync(sync_type="objects",
                                                    realm=config.realm,
                                                    site=config.site,
                                                    max_tries=10,
                                                    ignore_changed_objects=True,
                                                    skip_object_deletion=False,
                                                    socket_uri=socket_uri)
            except Exception as e:
                sync_status = False
                msg = "Initial sync of objects failed: %s" % e
                self.logger.warning(msg)
            if sync_status is False:
                current_try += 1
                if current_try >= max_tries:
                    msg = "Initial sync failed after %s tries." % max_tries
                    self.logger.warning(msg)
                    return
                time.sleep(1)
                continue
            if self.host_name not in multiprocessing.master_sync_done:
                multiprocessing.master_sync_done.append(self.host_name)
            msg = "Initial sync with master node finished."
            self.logger.info(msg)
            break

    def start_cluster_communication(self):
        """ Start cluster communication. """
        try:
            self._start_cluster_communication()
        except Exception as e:
            msg = "Error in cluster communication method: %s" % e
            self.logger.critical(msg)

    def _start_cluster_communication(self):
        """ Start cluster communication. """
        # Set proctitle.
        new_proctitle = "%s (Cluster communication)" % self.full_name
        setproctitle.setproctitle(new_proctitle)
        def signal_handler(_signal, frame):
            if _signal != 15:
                return
            # Close all cluster connections.
            self.close_cluster_connections()
            # Cleanup IPC stuff.
            multiprocessing.cleanup()
            # Finally exit.
            os._exit(0)
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)

        # Update logger with new PID and daemon name.
        self.pid = os.getpid()
        log_banner = "%s:" % self.full_name
        self.logger = config.setup_logger(banner=log_banner,
                                        pid=self.pid,
                                        existing_logger=config.logger)
        multiprocessing.master_node.clear()
        multiprocessing.init_sync_done.clear()
        multiprocessing.master_sync_done.clear()
        multiprocessing.init_sync_running.clear()
        multiprocessing.radius_reload_queue.clear()
        multiprocessing.nsscache_sync_queue.clear()

        config.cluster_status = False
        config.cluster_vote_participation = True

        quorum_check_interval = 3
        quorum_message_sent = False
        wait_for_second_node = True
        second_node_wait_timeout = 0
        while True:
            # Handle node connections.
            self.handle_node_connections()

            # Get quorum.
            current_votes, required_votes, quorum = self.calc_quorum()

            quorum_msg = ("Gained quorum %s (%s required)"
                        % (current_votes, required_votes))
            no_quorum_msg = ("Waiting for quorum %s (%s required)"
                        % (current_votes, required_votes))
            if quorum:
                if not quorum_message_sent:
                    quorum_message_sent = True
                    self.logger.info(quorum_msg)
            else:
                quorum_message_sent = False
                self.logger.warning(no_quorum_msg)

            do_master_node_election = True
            if not quorum:
                time.sleep(quorum_check_interval)
                continue

            if config.start_freeradius:
                # Start freeradius.
                if config.cluster_status:
                    self.start_freeradius()
                else:
                    # Stop freeradius.
                    self.stop_freeradius()

            # For two node clusters wait 30 seconds for first node to appear.
            if wait_for_second_node:
                if required_votes == 1:
                    if current_votes == 1:
                        second_node_wait_timeout += 1
                        if second_node_wait_timeout < config.two_node_timeout:
                            do_master_node_election = False
                        else:
                            wait_for_second_node = False
                    else:
                        wait_for_second_node = False
                        msg = "Second node is online."
                        self.logger.info(msg)

            # Do master node election.
            if not do_master_node_election:
                if wait_for_second_node:
                    msg = "Waiting for second node..."
                    self.logger.info(msg)
                time.sleep(quorum_check_interval)
                continue

            try:
                new_master_node = self.do_master_node_election()
            except MasterNodeElectionFailed as e:
                self.logger.critical(e)
                time.sleep(quorum_check_interval)
                continue
            except Exception as e:
                msg = "Error in master node election method: %s" % e
                self.logger.critical(msg)
                time.sleep(quorum_check_interval)
                continue
            try:
                current_master_node = multiprocessing.master_node['master']
            except:
                current_master_node = None
            if current_master_node == new_master_node:
                time.sleep(quorum_check_interval)
                #config.master_failover = False
                config.cluster_status = True
                continue

            try:
                self.switch_master_node(current_master_node, new_master_node)
            except Exception as e:
                msg = "Failed to switch master node: %s" % e
                self.logger.critical(msg)
            config.master_failover = False
            config.cluster_status = True
            time.sleep(quorum_check_interval)

    def handle_two_node_setup(self):
        # Two node setups require some special handling if second node is down.
        if not config.two_node_setup:
            return
        if len(multiprocessing.member_nodes) != 0:
            return
        try:
            self.handle_events()
        except Exception as e:
            msg = "Failed to handle events: %s" % e
            self.logger.critical(msg)
            #print(msg)

    def start_cluster_connection(self, *args, **kwargs):
        """ Start cluster connection. """
        try:
            self._start_cluster_connection(*args, **kwargs)
        except Exception as e:
            msg = "Error in cluster connection method: %s" % e
            self.logger.critical(msg)
            config.raise_exception()

    def _start_cluster_connection(self, node_name):
        """ Start cluster communication with node. """
        # Set proctitle.
        new_proctitle = ("%s Cluster sync (%s)"
                        % (self.full_name, node_name))
        setproctitle.setproctitle(new_proctitle)

        conn_even_name = self.get_conn_event_name(node_name)
        conn_event = multiprocessing.Event(conn_even_name)

        def signal_handler(_signal, frame):
            if _signal != 15:
                return
            # Cleanup IPC stuff.
            if self.node_conn:
                self.node_conn.close()
            conn_event.unlink()
            multiprocessing.cleanup()
            os._exit(0)
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)

        # Update logger with new PID and daemon name.
        self.pid = os.getpid()
        log_banner = "%s:" % self.full_name
        self.logger = config.setup_logger(banner=log_banner,
                                        pid=self.pid,
                                        existing_logger=config.logger)
        start_over= True
        while True:
            # Wait for cluster event.
            if start_over:
                time.sleep(0.0001)
            else:
                #print("waiting for cluster event: %s" % node_name)
                conn_event.wait(timeout=3)
                conn_event.clear()
                #print("got event", node_name)

            # Handle two node cluster stuff.
            self.handle_two_node_setup()

            # If the node is not online but we have a sane cluster status
            # we can delete cluster journal entries that were written to
            # all member nodes.
            if node_name not in multiprocessing.online_nodes:
                if config.cluster_status:
                    for journal_entry_dir in self.get_cluster_journal():
                        entry_timestamp = os.path.basename(journal_entry_dir)
                        cluster_journal_entry = ClusterJournalEntry(timestamp=entry_timestamp)
                        try:
                            cluster_journal_entry.load()
                        except NotFound:
                            continue
                        except Exception as e:
                            msg = ("Failed to load cluster journal entry: %s: %s"
                                    % (entry_timestamp, e))
                            config.logger.critical(msg)
                            continue
                        if not self.check_member_nodes(cluster_journal_entry):
                            continue
                        self.check_online_nodes(cluster_journal_entry)

            #print("loop", node_name, multiprocessing.online_nodes)
            start_over= False
            if not self.do_node_check(node_name):
                start_over = True
                continue

            if not config.cluster_status:
                start_over = True
                continue

            if config.master_failover:
                start_over = True
                continue

            try:
                start_over = self.handle_cluster_journal(node_name)
            except Exception as e:
                start_over = True
                msg = "Failed to handle cluster journal: %s" % e
                self.logger.critical(msg)
                #print(msg)

            # Add node to cluster.
            if self.member_candidate:
                self.member_candidate = False
                multiprocessing.member_nodes[node_name] = True

            try:
                self.handle_nsscache_sync(node_name)
            except Exception as e:
                start_over = True
                msg = "nsscache sync request failed: %s" % e
                self.logger.critical(msg)

            try:
                self.handle_radius_reload(node_name)
            except Exception as e:
                start_over = True
                msg = "Radius reload request failed: %s" % e
                self.logger.critical(msg)

    def handle_cluster_journal(self, node_name):
        global node_checksums
        global processed_journal_entries
        if len(node_checksums) > 102400:
            node_checksums = node_checksums[51200:]
        if len(processed_journal_entries) > 102400:
            processed_journal_entries = processed_journal_entries[51200:]
        if not config.cluster_status:
            return True
        uuids_to_process = []
        entries_to_process = []
        cluster_journal_dirs = self.get_cluster_journal()
        for journal_entry_dir in cluster_journal_dirs:
            if not config.cluster_status:
                return True
            entry_timestamp = os.path.basename(journal_entry_dir)
            if entry_timestamp in processed_journal_entries:
                continue
            cluster_journal_entry = ClusterJournalEntry(timestamp=entry_timestamp)
            try:
                cluster_journal_entry.load()
            except NotFound:
                continue
            except Exception as e:
                msg = ("Failed to load cluster journal entry: %s: %s"
                        % (entry_timestamp, e))
                config.logger.critical(msg)
                continue
            entries_to_process.append(cluster_journal_entry.timestamp)
            if cluster_journal_entry.action != "delete":
                uuids_to_process.append(cluster_journal_entry.object_uuid)

        written_entries = []
        unsync_status_set = False
        objects_sync_started = True
        objects_sync_successful = False
        for entry_timestamp in entries_to_process:
            if not config.cluster_status:
                return True
            if entry_timestamp in processed_journal_entries:
                continue
            self.handle_two_node_setup()
            cluster_journal_entry = ClusterJournalEntry(timestamp=entry_timestamp)
            try:
                cluster_journal_entry.load()
            except NotFound:
                continue
            except Exception as e:
                msg = ("Failed to load cluster journal entry: %s: %s"
                        % (entry_timestamp, e))
                config.logger.critical(msg)
                continue
            #print(node_name, cluster_journal_entry.action, cluster_journal_entry.object_id)
            action = cluster_journal_entry.action
            object_id = cluster_journal_entry.object_id
            object_id = oid.get(object_id)
            object_uuid = cluster_journal_entry.object_uuid
            object_config = cluster_journal_entry.object_config
            object_checksum = cluster_journal_entry.object_checksum

            # Skip duplicated entries we've already written.
            # We only need to write the first and the last occurence.
            if action == "delete":
                try:
                    uuids_to_process.remove(object_uuid)
                except ValueError:
                    pass
            else:
                if object_uuid in written_entries:
                    if object_uuid in uuids_to_process:
                        msg = ("Skipping duplicated cluster journal entry: %s"
                                % (object_id))
                        self.logger.debug(msg)
                        try:
                            uuids_to_process.remove(object_uuid)
                        except ValueError:
                            pass
                        cluster_journal_entry.delete()
                        continue

            if object_checksum in node_checksums:
                node_checksums.append(object_checksum)
                cluster_journal_entry.add_node(node_name)
                processed_journal_entries.append(cluster_journal_entry.timestamp)
                # Check if object was written to member nodes
                if self.check_member_nodes(cluster_journal_entry):
                    # Check if object was written to all online nodes.
                    self.check_online_nodes(cluster_journal_entry)
                continue
            # Write object to peer.
            if node_name in cluster_journal_entry.get_nodes():
                processed_journal_entries.append(cluster_journal_entry.timestamp)
            else:
                # Mark node as out of sync (tree objects).
                if object_id.object_type in config.tree_object_types:
                    objects_sync_started = True
                    objects_sync_successful = True
                    # Make sure node we will write tree data to has the right master node.
                    try:
                        master_node = self.node_conn.get_master_node()
                    except (ConnectionTimeout, ConnectionError, ConnectionQuit) as e:
                        self.node_leave(node_name)
                        msg = ("Failed to get master node: %s: %s"
                                % (node_name, e))
                        self.logger.warning(msg)
                        return False
                    except Exception as e:
                        msg = ("Failed to get master node: %s: %s"
                                % (node_name, e))
                        self.logger.warning(msg)
                        return True
                    if master_node != self.host_name:
                        try:
                            cluster_journal_entry.delete()
                        except Exception as e:
                            msg = "Failed to delete cluster journal entry."
                            self.logger.critical(msg)
                        break
                    if not unsync_status_set:
                        unsync_status_set = True
                        self.unset_node_sync(node_name)
                if action == "write":
                    last_modified = cluster_journal_entry.last_modified
                    try:
                        last_used = backend.get_last_used(object_id.realm,
                                                        object_id.site,
                                                        object_id.object_type,
                                                        object_uuid)
                    except Exception as e:
                        msg = "Failed to get last used time: %s" % object_id
                        self.logger.warning(msg)
                        continue
                    try:
                        write_status = self.node_conn.write(object_id.full_oid,
                                                            object_config,
                                                            last_modified,
                                                            last_used)
                    except (ConnectionTimeout, ConnectionError, ConnectionQuit) as e:
                        self.node_leave(node_name)
                        msg = ("Failed to send object: %s: %s: %s"
                                % (node_name, object_id, e))
                        self.logger.warning(msg)
                        return True
                    except Exception as e:
                        msg = ("Failed to send object: %s: %s: %s"
                                % (node_name, object_id, e))
                        self.logger.warning(msg)
                        return True
                    if write_status != "done":
                        objects_sync_successful = False
                        continue
                    written_entries.append(object_uuid)
                    try:
                        uuids_to_process.remove(object_uuid)
                    except ValueError:
                        pass
                    msg = ("Written object to node: %s: %s (%s)"
                            % (node_name, object_id, object_checksum))
                    self.logger.debug(msg)
                    cluster_journal_entry.add_node(node_name)
                    processed_journal_entries.append(cluster_journal_entry.timestamp)
                # Rename object on peer.
                if action == "rename":
                    new_object_id = cluster_journal_entry.new_object_id
                    new_object_id = oid.get(new_object_id)
                    try:
                        rename_status = self.node_conn.rename(object_id.full_oid,
                                                            new_object_id.full_oid)
                    except (ConnectionTimeout, ConnectionError, ConnectionQuit) as e:
                        self.node_leave(node_name)
                        msg = ("Failed to rename object: %s: %s: %s"
                                % (node_name, object_id, e))
                        self.logger.warning(msg)
                        return True
                    except Exception as e:
                        msg = ("Failed to rename object: %s: %s: %s"
                                % (node_name, object_id, e))
                        self.logger.warning(msg)
                        return True
                    if rename_status != "done":
                        objects_sync_successful = False
                        continue
                    written_entries.append(object_uuid)
                    try:
                        uuids_to_process.remove(object_uuid)
                    except ValueError:
                        pass
                    msg = ("Renamed object on node: %s: %s: %s"
                            % (node_name, object_id, new_object_id))
                    self.logger.debug(msg)
                    cluster_journal_entry.add_node(node_name)
                    processed_journal_entries.append(cluster_journal_entry.timestamp)
                # Delete object on peer.
                if action == "delete":
                    try:
                        del_status = self.node_conn.delete(object_uuid,
                                                        object_id.full_oid)
                    except (ConnectionTimeout, ConnectionError, ConnectionQuit) as e:
                        self.node_leave(node_name)
                        msg = "Failed to delete object: %s: %s" % (object_id, e)
                        self.logger.warning(msg)
                        return True
                    except Exception as e:
                        msg = "Failed to delete object: %s: %s" % (object_id, e)
                        self.logger.warning(msg)
                        return True
                    if del_status != "done":
                        objects_sync_successful = False
                        continue
                    msg = ("Deleted object on node: %s: %s"
                            % (node_name, object_id))
                    self.logger.debug(msg)
                    cluster_journal_entry.add_node(node_name)
                    processed_journal_entries.append(cluster_journal_entry.timestamp)

            # Check if object was written to member nodes.
            if self.check_member_nodes(cluster_journal_entry):
                # Check if object was written to all online nodes.
                self.check_online_nodes(cluster_journal_entry)

        if config.master_node:
            if objects_sync_started and objects_sync_successful:
                sync_time = time.time()
                config.touch_node_sync_file(sync_time)
                # Mark node as in sync (tree objects).
                self.set_node_sync(node_name, sync_time-300)

        journal_entries = self.get_cluster_journal()
        if journal_entries:
            return True
        sync_time = time.time()
        return False

    def set_node_sync(self, node_name, sync_time):
        try:
            self.node_conn.set_node_sync(sync_time)
        except (ConnectionTimeout, ConnectionError, ConnectionQuit) as e:
            self.node_leave(node_name)
            msg = ("Failed to set cluster sync state: %s: %s"
                    % (node_name, e))
            self.logger.warning(msg)
        except Exception as e:
            msg = ("Failed to set cluster sync state: %s: %s"
                    % (node_name, e))
            self.logger.warning(msg)

    def unset_node_sync(self, node_name):
        try:
            self.node_conn.unset_node_sync()
        except (ConnectionTimeout, ConnectionError, ConnectionQuit) as e:
            self.node_leave(node_name)
            msg = ("Failed to unset cluster sync state: %s: %s"
                    % (node_name, e))
            self.logger.warning(msg)
        except Exception as e:
            msg = ("Failed to unset cluster sync state: %s: %s"
                    % (node_name, e))
            self.logger.warning(msg)

    def check_online_nodes(self, cluster_journal_entry):
        online_nodes_in_sync = True
        for node_name in multiprocessing.online_nodes:
            if node_name in cluster_journal_entry.get_nodes():
                continue
            online_nodes_in_sync = False
        if not online_nodes_in_sync:
            return
        try:
            cluster_journal_entry.delete()
        except Exception as e:
            msg = "Failed to delete cluster journal entry."
            self.logger.critical(msg)

    def check_member_nodes(self, cluster_journal_entry):
        member_nodes_in_sync = True
        for node_name in multiprocessing.member_nodes:
            if node_name in cluster_journal_entry.get_nodes():
                continue
            member_nodes_in_sync = False
        if not member_nodes_in_sync:
            return False
        object_event_name = "/%s" % cluster_journal_entry.timestamp
        object_event = multiprocessing.Event(object_event_name)
        object_event.set()
        object_event.unlink()
        return True

    def handle_nsscache_sync(self, node_name):
        # Handle nsscache sync requests.
        for sync_time in multiprocessing.nsscache_sync_queue:
            if float(sync_time) > time.time():
                continue
            try:
                node_list = multiprocessing.nsscache_sync_queue[sync_time]
            except KeyError:
                continue
            if node_name in node_list:
                continue
            node_list.append(node_name)
            sync_sent_to_all_nodes = True
            for x_node in multiprocessing.member_nodes:
                if x_node in node_list:
                    continue
                sync_sent_to_all_nodes = False
                break
            if sync_sent_to_all_nodes:
                try:
                    multiprocessing.nsscache_sync_queue.pop(sync_time)
                except KeyError:
                    pass
            else:
                try:
                    multiprocessing.nsscache_sync_queue[sync_time] = node_list
                except KeyError:
                    pass
            # Send sync request.
            try:
                self.node_conn.do_nsscache_sync()
            except Exception as e:
                self.node_leave(node_name)
                msg = "Failed to send nsscache sync request: %s" % e
                self.logger.warning(msg)
                continue
            msg = "nsscache sync request sent to node: %s" % node_name
            self.logger.info(msg)

    def handle_radius_reload(self, node_name):
        # Handle radius reload requests.
        for reload_time in multiprocessing.radius_reload_queue:
            if float(reload_time) > time.time():
                continue
            try:
                node_list = multiprocessing.radius_reload_queue[reload_time]
            except KeyError:
                continue
            if node_name in node_list:
                continue
            node_list.append(node_name)
            all_nodes_reloaded = True
            for x_node in multiprocessing.member_nodes:
                if x_node in node_list:
                    continue
                all_nodes_reloaded = False
                break
            if all_nodes_reloaded:
                try:
                    multiprocessing.radius_reload_queue.pop(reload_time)
                except KeyError:
                    pass
            else:
                try:
                    multiprocessing.radius_reload_queue[reload_time] = node_list
                except KeyError:
                    pass
            # Make sure radius gets reloaded (after objects have changed.).
            try:
                self.node_conn.do_radius_reload()
            except Exception as e:
                self.node_leave(node_name)
                msg = "Failed to send radius reload request: %s" % e
                self.logger.warning(msg)
                break
            msg = "Radius reload request sent to node: %s" % node_name
            self.logger.info(msg)

    def start_freeradius(self):
        from otpme.lib.freeradius import start
        from otpme.lib.freeradius import status
        try:
            status()
            freeradius_running = True
        except:
            freeradius_running = False
        if freeradius_running:
            return
        try:
            start()
        except Exception as e:
            msg = "Failed to start freeradius: %s" % e
            self.logger.critical(msg)
        else:
            msg = "Started freeradius."
            self.logger.info(msg)

    def stop_freeradius(self):
        from otpme.lib.freeradius import stop
        from otpme.lib.freeradius import status
        try:
            status()
            freeradius_running = True
        except:
            freeradius_running = False
        if not freeradius_running:
            return
        try:
            stop()
        except Exception as e:
            msg = "Failed to stop freeradius: %s" % e
            self.logger.critical(msg)
        else:
            msg = "Stopped freeradius."
            self.logger.info(msg)

    def close_cluster_connections(self):
        """ Close all cluster connections. """
        for node_name in dict(self.cluster_connections):
            cluster_proc = self.cluster_connections[node_name]
            cluster_proc.terminate()
            cluster_proc.join()
            self.cluster_connections.pop(node_name)
            self.node_leave(node_name)
            try:
                multiprocessing.online_nodes.pop(node_name)
            except KeyError:
                pass
            try:
                multiprocessing.init_sync_done.remove(node_name)
            except ValueError:
                pass
            try:
                multiprocessing.init_sync_running.remove(node_name)
            except ValueError:
                pass

    def _run(self, **kwargs):
        """ Start daemon loop. """
        # FIXME: where to configure max_conn?
        # Set max client connections.
        self.max_conn = 100
        # Set signal handler.
        signal.signal(signal.SIGTERM, self.signal_handler)
        signal.signal(signal.SIGINT, self.signal_handler)
        multiprocessing.node_votes.clear()
        # Initially we dont have quorum.
        config.cluster_quorum = False
        multiprocessing.cluster_quorum.clear()
        multiprocessing.sync_nodes.clear()
        # Configure ourselves (e.g. certificates etc.).
        try:
            self.configure()
        except Exception as e:
            msg = "Failed to configure %s" % self.name
            self.logger.critical(msg)
        # All protocols we support.
        self.protocols = config.get_otpme_protocols(self.name, server=True)
        # Set socket banner.
        self.socket_banner = ("%s %s %s"
                            % (status_codes.OK,
                            self.full_name,
                            config.my_version))

        # Add default connection handler.
        try:
            self.set_connection_handler()
        except Exception as e:
            msg = "Failed to set connection handler: %s" % e
            self.logger.critical(msg)

        # Setup sockets.
        self.setup_sockets()

        # We can drop privileges AFTER sockets are created. This is needed when
        # listening to well known ports (<1024), which requires root privileges.
        try:
            self.drop_privileges()
        except Exception as e:
            msg = "Failed to drop privileges: %s" % e
            self.logger.critical(msg)

        # Start listening on sockets.
        for s in self.sockets:
            try:
                s.listen()
            except Exception as e:
                msg = ("Unable to listen on socket: %s" % e)
                self.logger.critical(msg)

        # Notify controld that we are ready.
        try:
            self.comm_handler.send("controld", command="ready")
        except Exception as e:
            msg = "Failed to send read message to controld: %s" % e
            self.logger.critical(msg)

        self.logger.info("%s started" % self.full_name)

        # Wait for first keepalive packet that indicates all
        # daemons (e.g. syncd) are ready.
        try:
            sender, command, data = self.comm_handler.recv(sender="controld")
        except ExitOnSignal:
            return
        except Exception as e:
            msg = "Failed to receive daemon message: %s" % e
            self.logger.critical(msg)
            return
        if command != "ping":
            msg = "Received wrong command: %s" % command
            raise OTPmeException(msg)
        # Reply keepalive packet.
        self.comm_handler.send("controld", "pong")

        # Start child processes.
        self.start_childs()

        while True:
            try:
                # Try to read daemon message.
                try:
                    sender, \
                    daemon_command, \
                    data = self.comm_handler.recv()
                except ExitOnSignal:
                    break
                except TimeoutReached:
                    daemon_command = None
                except Exception as e:
                    msg = (_("Error receiving daemon message: %s") % e)
                    self.logger.critical(msg, exc_info=True)
                    raise OTPmeException(msg)

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
            except (KeyboardInterrupt, SystemExit):
                pass
            except Exception as e:
                msg = ("Unhandled error in clusterd: %s" % e)
                self.logger.critical(msg, exc_info=True)
                config.raise_exception()
