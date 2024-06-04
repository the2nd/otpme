# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time
import glob
import ujson
import shutil
import signal
import setproctitle
from functools import wraps

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
from otpme.lib import sign_key_cache
from otpme.lib import multiprocessing
from otpme.lib.protocols import status_codes
from otpme.lib.daemon.otpme_daemon import OTPmeDaemon
from otpme.lib.classes.object_config import ObjectConfig
from otpme.lib.freeradius import reload as freeradius_reload

from otpme.lib.exceptions import *

JOURNAL_LOCK_TYPE = "cluster_journal"

default_callback = config.get_callback()

REGISTER_BEFORE = ['otpme.lib.daemon.controld']
REGISTER_AFTER = []

CLUSTER_IN_JOURNAL_NAME = "cluster_in_journal"
CLUSTER_IN_JOURNAL_DIR = os.path.join(config.spool_dir, CLUSTER_IN_JOURNAL_NAME)
CLUSTER_OUT_JOURNAL_NAME = "cluster_out_journal"
CLUSTER_OUT_JOURNAL_DIR = os.path.join(config.spool_dir, CLUSTER_OUT_JOURNAL_NAME)
MEMBER_CANDIDATE_DIR_NAME = "member_candidate"
MEMBER_CANDIDATE_DIR = os.path.join(config.spool_dir, MEMBER_CANDIDATE_DIR_NAME)

def register():
    """ Register OTPme daemon. """
    config.register_otpme_daemon("clusterd")
    multiprocessing.register_shared_dict("sync_nodes")
    multiprocessing.register_shared_dict("ready_nodes")
    multiprocessing.register_shared_dict("master_node")
    multiprocessing.register_shared_dict("online_nodes")
    multiprocessing.register_shared_dict("member_nodes")
    multiprocessing.register_shared_list("pause_writes")
    multiprocessing.register_shared_dict("running_jobs")
    multiprocessing.register_shared_dict("cluster_quorum")
    multiprocessing.register_shared_dict("cluster_journal")
    multiprocessing.register_shared_dict("node_connections")
    multiprocessing.register_shared_list("master_sync_done")
    multiprocessing.register_shared_dict("member_candidates")
    multiprocessing.register_shared_dict("radius_reload_queue")
    multiprocessing.register_shared_dict("daemon_reload_queue")
    multiprocessing.register_shared_dict("nsscache_sync_queue")
    multiprocessing.register_shared_dict("peer_nodes_set_online")
    register_cluster_journal()

def register_cluster_journal():
    """ Directory to store cluster journal. """
    locking.register_lock_type(JOURNAL_LOCK_TYPE, module=__file__)
    config.register_config_var("cluster_in_journal_dir", str, CLUSTER_IN_JOURNAL_DIR)
    config.register_config_var("cluster_out_journal_dir", str, CLUSTER_OUT_JOURNAL_DIR)
    config.register_config_var("member_candidate_dir", str, MEMBER_CANDIDATE_DIR)
    backend.register_data_dir(name=CLUSTER_IN_JOURNAL_NAME,
                            path=CLUSTER_IN_JOURNAL_DIR,
                            drop=True,
                            perms=0o770)
    backend.register_data_dir(name=CLUSTER_OUT_JOURNAL_NAME,
                            path=CLUSTER_OUT_JOURNAL_DIR,
                            drop=True,
                            perms=0o770)
    backend.register_data_dir(name=MEMBER_CANDIDATE_DIR_NAME,
                            path=MEMBER_CANDIDATE_DIR,
                            drop=True,
                            perms=0o770)

def get_object_event(timestamp):
    object_event_name = "/cluster_journal_%s" % timestamp
    object_event = multiprocessing.Event(object_event_name)
    return object_event

def check_cluster_status():
    if config.master_failover:
        msg = "Ongoing master failover."
        raise OTPmeException(msg)
    if not config.cluster_quorum:
        msg = "No cluster quorum."
        raise OTPmeException(msg)
    if not config.cluster_status:
        msg = "Cluster not ready."
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
    if not multiprocessing.cluster_out_event:
        return
    multiprocessing.cluster_out_event.set()

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
    if not multiprocessing.cluster_out_event:
        return
    multiprocessing.cluster_out_event.set()

def cluster_daemon_reload():
    if config.use_api:
        return
    if config.one_node_setup:
        return
    multiprocessing.daemon_reload_queue.clear()
    reload_time = time.time() + 5
    try:
        multiprocessing.daemon_reload_queue[reload_time] = []
    except ValueError:
        pass
    if not multiprocessing.cluster_out_event:
        return
    multiprocessing.cluster_out_event.set()

def cluster_sync_object(object_uuid, object_id, action, object_config=None,
    new_object_id=None, checksum=None, index_journal=None, wait_for_write=True):
    if not multiprocessing.cluster_out_event:
        return
    if config.one_node_setup:
        return
    if config.two_node_setup:
        if len(multiprocessing.online_nodes) == 0:
            if action != "delete":
                return
            wait_for_write = False
    while len(multiprocessing.pause_writes) > 0:
        time.sleep(0.1)
    while True:
        try:
            cluster_journal_entry = ClusterJournalEntry(timestamp=time.time_ns(),
                                                    action=action,
                                                    object_uuid=object_uuid,
                                                    object_id=object_id,
                                                    checksum=checksum,
                                                    index_journal=index_journal,
                                                    object_config=object_config,
                                                    new_object_id=new_object_id)
        except AlreadyExists:
            continue
        else:
            break
    if not wait_for_write:
        try:
            cluster_journal_entry.commit()
        except Exception as e:
            msg = ("Failed to commit cluster journal entry: %s: %s"
                    % (object_id, e))
            config.logger.critical(msg)
            return
        multiprocessing.cluster_out_event.set()
        return
    object_event = get_object_event(cluster_journal_entry.timestamp)
    object_event.open()
    try:
        cluster_journal_entry.commit()
    except Exception as e:
        msg = ("Failed to commit cluster journal entry: %s: %s"
                % (object_id, e))
        config.logger.critical(msg)
        return
    multiprocessing.cluster_out_event.set()
    return object_event

def calc_node_vote():
    node_name = config.host_data['name']
    node_in_sync = False
    if node_name in multiprocessing.master_sync_done:
        node_in_sync = True
    if node_in_sync:
        result = backend.search(object_type="node",
                                attribute="name",
                                value=node_name,
                                return_type="instance")
        if not result:
            return 0
        node = result[0]
        node_vote = node.get_node_vote()
    else:
        node_vote = {'revision':1, 'vote':0}
    return node_vote

def entry_lock(write=True, timeout=None):
    """ Decorator to handle entry lock. """
    def wrapper(f):
        @wraps(f)
        def wrapped(self, *f_args, **f_kwargs):
            self.lock(write=write)
            # Call given class method.
            try:
                result = f(self, *f_args, **f_kwargs)
            finally:
                self.release()
            return result
        return wrapped
    return wrapper

class ClusterEntry(object):
    """ Cluster entry base class. """
    def __init__(self, journal_dir, timestamp, _lock_type, action=None, **kwargs):
        self._lock = None
        self._lock_type = _lock_type
        self.logger = config.logger
        self.timestamp = timestamp
        self.entry_dir = os.path.join(journal_dir, str(self.timestamp))
        self.nodes_dir = os.path.join(self.entry_dir, "nodes")
        self.action_file = os.path.join(self.entry_dir, "action")
        self.commit_file = os.path.join(self.entry_dir, "ready")
        self.failed_nodes_dir = os.path.join(self.entry_dir, "failed_nodes")
        if action:
            if os.path.exists(self.entry_dir):
                msg = "Entry already exists: %s" % self.entry_dir
                raise AlreadyExists(msg)
        if action is not None:
            try:
                filetools.create_dir(self.entry_dir)
            except FileExistsError:
                pass
            try:
                filetools.create_dir(self.nodes_dir)
            except FileExistsError:
                pass
            try:
                filetools.create_dir(self.failed_nodes_dir)
            except FileExistsError:
                pass
        if action is not None:
            self.action = action

    def lock(self, write=False):
        if self._lock:
            return
        self._lock = locking.acquire_lock(lock_type=self._lock_type,
                                            lock_id=self.timestamp,
                                            write=write)
        if not os.path.exists(self.entry_dir):
            msg = "Entry deleted while waiting for lock: %s" % self.timestamp
            self.release()
            raise ObjectDeleted(msg)

    def release(self):
        if not self._lock:
            return
        self._lock.release_lock()
        self._lock = None

    @property
    @entry_lock(write=False)
    def action(self):
        try:
            action = filetools.read_file(self.action_file)
        except FileNotFoundError:
            action = None
        except Exception as e:
            action = None
            msg = "Failed to read action from cluster entry: %s" % e
            self.logger.critical(msg)
        return action

    @action.setter
    #@entry_lock(write=True)
    def action(self, action):
        try:
            filetools.create_file(path=self.action_file,
                                    content=action)
        except Exception as e:
            msg = ("Failed to add action to cluster entry: %s: %s"
                    % (self.timestamp, e))
            self.logger.critical(msg)

    @property
    @entry_lock(write=True)
    def pid(self):
        try:
            pid = filetools.read_file(self.commit_file)
        except FileNotFoundError:
            pid = None
        if pid:
            pid = int(pid)
        return pid

    @property
    @entry_lock(write=False)
    def committed(self):
        if os.path.exists(path=self.commit_file):
            return True
        return False

    @entry_lock(write=True)
    def commit(self):
        try:
            filetools.create_file(path=self.commit_file,
                                content=str(os.getpid()))
        except Exception as e:
            msg = ("Failed to commit cluster entry: %s: %s"
                    % (self.timestamp, e))
            self.logger.critical(msg)

    @entry_lock(write=True)
    def add_node(self, node_name):
        node_file = os.path.join(self.nodes_dir, node_name)
        try:
            filetools.create_file(path=node_file, content=str(time.time()))
        except Exception as e:
            msg = ("Failed to add node to cluster entry: %s: %s"
                    % (node_name, e))
            self.logger.critical(msg)

    @entry_lock(write=False)
    def get_nodes(self):
        nodes = []
        for node_file in sorted(glob.glob(self.nodes_dir + "/*")):
            node_name = os.path.basename(node_file)
            nodes.append(node_name)
        return nodes

    @entry_lock(write=True)
    def add_failed_node(self, node_name):
        node_file = os.path.join(self.failed_nodes_dir, node_name)
        try:
            filetools.create_file(path=node_file, content=str(time.time()))
        except Exception as e:
            msg = ("Failed to add failed node to cluster entry: %s: %s"
                    % (node_name, e))
            self.logger.critical(msg)

    @entry_lock(write=False)
    def get_failed_nodes(self):
        nodes = []
        for node_file in sorted(glob.glob(self.failed_nodes_dir + "/*")):
            node_name = os.path.basename(node_file)
            nodes.append(node_name)
        return nodes

    @entry_lock(write=True)
    def delete(self):
        object_id = self.object_id
        entry_del_dir = "%s.deleting" % self.entry_dir
        try:
            os.rename(self.entry_dir, entry_del_dir)
        except FileNotFoundError:
            return
        except Exception as e:
            msg = "Failed to rename entry dir: %s: %s" % (self.entry_dir, e)
            self.logger.critical(msg)
            return
        try:
            shutil.rmtree(entry_del_dir)
        except FileNotFoundError:
            pass
        except Exception as e:
            msg = ("Failed to remove cluster entry nodes dir: %s: %s"
                    % (self.entry_dir, e))
            self.logger.warning(msg)
        msg = ("Deleted cluster entry: %s" % object_id)
        self.logger.debug(msg)

class ClusterJournalEntry(ClusterEntry):
    """ Cluster journal entry. """
    def __init__(self, timestamp, object_uuid=None, action=None,
        object_id=None, checksum=None, object_config=None,
        index_journal=None, new_object_id=None):
        journal_dir = config.cluster_out_journal_dir
        super(ClusterJournalEntry, self).__init__(journal_dir=journal_dir,
                                                    _lock_type=JOURNAL_LOCK_TYPE,
                                                    timestamp=timestamp,
                                                    action=action)
        self.object_id_file = os.path.join(self.entry_dir, "object_id")
        self.object_uuid_file = os.path.join(self.entry_dir, "object_uuid")
        self.new_object_id_file = os.path.join(self.entry_dir, "new_object_id")
        self.object_checksum_file = os.path.join(self.entry_dir, "object_checksum")
        self.index_journal_file = os.path.join(self.entry_dir, "index_journal")
        if action is not None:
            self.action = action
        if object_id is not None:
            self.object_id = object_id
        if object_uuid is not None:
            self.object_uuid = object_uuid
        if object_config is not None:
            self.object_config = object_config
        if index_journal is not None:
            self.index_journal = index_journal
        if checksum is not None:
            self.object_checksum = checksum
        if new_object_id is not None:
            self.new_object_id = new_object_id

    def __str__(self):
        return self.timestamp

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

    @property
    @entry_lock(write=False)
    def object_id(self):
        try:
            object_id = filetools.read_file(self.object_id_file)
        except FileNotFoundError:
            object_id = None
        except Exception as e:
            object_id = None
            msg = ("Failed to read object ID from cluster entry: %s: %s"
                    % (self.timestamp, e))
            self.logger.critical(msg)
        return object_id

    @object_id.setter
    #@entry_lock(write=True)
    def object_id(self, object_id):
        try:
            filetools.create_file(path=self.object_id_file,
                                    content=object_id.full_oid)
        except Exception as e:
            msg = ("Failed to add object ID to cluster entry: %s: %s"
                    % (self.timestamp, e))
            self.logger.critical(msg)

    @property
    @entry_lock(write=False)
    def new_object_id(self):
        try:
            new_object_id = filetools.read_file(self.new_object_id_file)
        except FileNotFoundError:
            new_object_id = None
        except Exception as e:
            new_object_id = None
            msg = ("Failed to read new object ID from cluster entry: %s: %s"
                    % (self.timestamp, e))
            self.logger.critical(msg)
        return new_object_id

    @new_object_id.setter
    #@entry_lock(write=True)
    def new_object_id(self, new_object_id):
        try:
            filetools.create_file(path=self.new_object_id_file,
                                    content=new_object_id.full_oid)
        except Exception as e:
            msg = ("Failed to add new object ID to cluster entry: %s: %s"
                    % (self.timestamp, e))
            self.logger.critical(msg)

    @property
    @entry_lock(write=False)
    def object_uuid(self):
        try:
            object_uuid = filetools.read_file(self.object_uuid_file)
        except FileNotFoundError:
            object_uuid = None
        except Exception as e:
            object_uuid = None
            msg = ("Failed to read object UUID from cluster entry: %s: %s"
                    % (self.timestamp, e))
            self.logger.critical(msg)
        return object_uuid

    @object_uuid.setter
    #@entry_lock(write=True)
    def object_uuid(self, object_uuid):
        try:
            filetools.create_file(path=self.object_uuid_file,
                                    content=object_uuid)
        except Exception as e:
            msg = ("Failed to add object UUID to cluster entry: %s: %s"
                    % (self.timestamp, e))
            self.logger.critical(msg)

    @property
    @entry_lock(write=False)
    def object_checksum(self):
        try:
            object_checksum = filetools.read_file(self.object_checksum_file)
        except FileNotFoundError:
            object_checksum = None
        except Exception as e:
            object_checksum = None
            msg = ("Failed to read object checksum from cluster entry: %s: %s"
                    % (self.timestamp, e))
            self.logger.critical(msg)
        return object_checksum

    @object_checksum.setter
    #@entry_lock(write=True)
    def object_checksum(self, object_checksum):
        try:
            filetools.create_file(path=self.object_checksum_file,
                                    content=object_checksum)
        except Exception as e:
            msg = ("Failed to add object checksum to cluster entry: %s: %s"
                    % (self.timestamp, e))
            self.logger.critical(msg)

    @property
    @entry_lock(write=False)
    def index_journal(self):
        try:
            index_journal = filetools.read_file(self.index_journal_file)
        except FileNotFoundError:
            index_journal = None
        except Exception as e:
            index_journal = None
            msg = ("Failed to read index journal from cluster entry: %s: %s"
                    % (self.timestamp, e))
            self.logger.critical(msg)
        index_journal = ujson.loads(index_journal)
        return index_journal

    @index_journal.setter
    #@entry_lock(write=True)
    def index_journal(self, index_journal):
        index_journal = ujson.dumps(index_journal)
        try:
            filetools.create_file(path=self.index_journal_file,
                                    content=index_journal)
        except Exception as e:
            msg = ("Failed to add index journal to cluster entry: %s: %s"
                    % (self.timestamp, e))
            self.logger.critical(msg)

    @property
    @entry_lock(write=False)
    def object_config(self):
        try:
            object_config = multiprocessing.cluster_journal[self.timestamp]
        except KeyError:
            object_config = None
        return object_config

    @object_config.setter
    #@entry_lock(write=True)
    def object_config(self, object_config):
        multiprocessing.cluster_journal[self.timestamp] = object_config

    @entry_lock(write=True)
    def delete(self):
        try:
            multiprocessing.cluster_journal.pop(self.timestamp)
        except KeyError:
            pass
        super(ClusterJournalEntry, self).delete()

class ClusterDaemon(OTPmeDaemon):
    """ ClusterDaemon. """
    def __init__(self, *args, **kwargs):
        self.node_conn = None
        self.node_name = None
        self.conn_event = None
        self.node_offline = False
        self.node_check_connections = {}
        self.node_write_connections = {}
        self.lock_proc_event = None
        self.cluster_comm_child = None
        self.two_node_handler_child = None
        self.interprocess_comm_child = None
        self.cluster_in_journal_child = None
        self._processed_journal_entries = []
        self.all_nodes = []
        self.member_nodes = []
        self.online_nodes = []
        super(ClusterDaemon, self).__init__(*args, **kwargs)

    def signal_handler(self, _signal, frame):
        """ Exit on signal. """
        if _signal != 15:
            if _signal != 2:
                return
        # Act only on our own PID.
        if os.getpid() != self.pid:
            return
        msg = ("Received SIGTERM.")
        self.logger.info(msg)
        if config.start_freeradius:
            self.stop_freeradius()
        self.close_childs()
        return super(ClusterDaemon, self).signal_handler(_signal, frame)

    def clear_processed_journal_entries(self):
        all_nodes = backend.search(object_type="node",
                            attribute="uuid",
                            value="*",
                            realm=config.realm,
                            site=config.site,
                            return_type="name")
        if self.all_nodes != sorted(all_nodes):
            self.all_nodes = sorted(all_nodes)
            self._processed_journal_entries.clear()

        if self.online_nodes != sorted(multiprocessing.online_nodes.keys()):
            self.online_nodes = sorted(multiprocessing.online_nodes.keys())
            self._processed_journal_entries.clear()

        if self.member_nodes != sorted(multiprocessing.member_nodes.keys()):
            self.member_nodes = sorted(multiprocessing.member_nodes.keys())
            self._processed_journal_entries.clear()

        if self.member_candidate:
            self._processed_journal_entries.clear()

    @property
    def processed_journal_entries(self):
        self.clear_processed_journal_entries()
        return self._processed_journal_entries

    @processed_journal_entries.setter
    def processed_journal_entries(self, _list):
        self._processed_journal_entries = _list
        self.clear_processed_journal_entries()

    @property
    def member_candidate(self):
        try:
            member_candidate = multiprocessing.member_candidates[self.node_name]
        except KeyError:
            member_candidate = False
        return member_candidate

    @member_candidate.setter
    def member_candidate(self, value):
        multiprocessing.member_candidates[self.node_name] = value

    def start_childs(self, reload=False):
        """ Start child processes childs. """
        msg = "Starting cluster communication..."
        self.logger.info(msg)
        # Interprocess communication.
        self.interprocess_comm_child = multiprocessing.start_process(name=self.name,
                                        target=self.start_interprocess_comm)
        # Start cluster communication.
        self.cluster_comm_child = multiprocessing.start_process(name=self.name,
                                        target=self.start_cluster_communication,
                                        target_kwargs={'reload':reload})
        # Start in journal handler.
        self.cluster_in_journal_child = multiprocessing.start_process(name=self.name,
                                        target=self.start_in_journal_handler)

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
        if self.cluster_comm_child:
            try:
                self.cluster_comm_child.terminate()
                self.cluster_comm_child.join()
            except Exception as e:
                msg = "Failed to stop cluster communication child: %s" % e
                self.logger.warning(msg)
        if self.cluster_in_journal_child:
            try:
                self.cluster_in_journal_child.terminate()
                self.cluster_in_journal_child.join()
            except Exception as e:
                msg = "Failed to stop cluster in-journal child: %s" % e
                self.logger.warning(msg)
        if self.two_node_handler_child:
            try:
                self.two_node_handler_child.terminate()
                self.two_node_handler_child.join()
            except Exception as e:
                msg = "Failed to stop two node child: %s" % e
                self.logger.warning(msg)

    @property
    def host_name(self):
        host_name = config.host_data['name']
        return host_name

    @property
    def host_type(self):
        host_type = config.host_data['type']
        return host_type

    def get_cluster_out_journal(self):
        journal_dirs = sorted(glob.glob(CLUSTER_OUT_JOURNAL_DIR + "/[0-9]*[!.deleting]"))
        return journal_dirs

    def get_cluster_in_journal(self):
        journal_files = sorted(glob.glob(CLUSTER_IN_JOURNAL_DIR + "/[0-9]*"))
        return journal_files

    def get_member_candidate_journal(self):
        journal_files = sorted(glob.glob(self.member_candidate_dir + "/[0-9]*"))
        return journal_files

    def clean_cluster_out_journal(self):
        for journal_entry in self.get_cluster_out_journal():
            entry_timestamp = os.path.basename(journal_entry)
            cluster_journal_entry = ClusterJournalEntry(timestamp=entry_timestamp)
            try:
                cluster_journal_entry.delete()
            except ObjectDeleted:
                pass

    def clean_cluster_in_journal(self):
        for journal_file in self.get_cluster_in_journal():
            os.remove(journal_file)

    def node_leave(self, node_name):
        self.node_disconnect(node_name)
        try:
            multiprocessing.member_nodes.pop(node_name)
        except KeyError:
            pass
        self.calc_quorum()

    def node_disconnect(self, node_name):
        try:
            multiprocessing.ready_nodes.pop(node_name)
        except KeyError:
            pass
        try:
            multiprocessing.online_nodes.pop(node_name)
        except KeyError:
            pass
        try:
            multiprocessing.peer_nodes_set_online.pop(node_name)
        except KeyError:
            pass
        self.node_conn = None

    def get_conn_event_name(self, node_name):
        conn_even_name = "/cjournal-event-%s" % node_name
        return conn_even_name

    def start_initial_sync(self, node_name):
        """ Start initial sync of sessions etc.. """
        while True:
            if config.daemon_shutdown:
                os._exit(0)
            try:
                clusterd_conn = self.get_clusterd_connection(node_name)
            except Exception as e:
                msg = ("Failed to get initial sync connection: %s: %s"
                        % (node_name, e))
                self.logger.warning(msg)
                time.sleep(1)
                continue
            msg = "Starting data sync with node: %s" % node_name
            self.logger.info(msg)
            try:
                clusterd_conn.sync()
                msg = "Data sync finished with node: %s" % node_name
                self.logger.info(msg)
                break
            except Exception as e:
                msg = "Failed to sync with node: %s: %s" % (node_name, e)
                self.logger.warning(msg)
                time.sleep(1)
                #config.raise_exception()

    def start_interprocess_comm(self):
        """ Start cluster interprocess communication. """
        # Set proctitle.
        new_proctitle = "%s (Cluster IPC)" % self.full_name
        setproctitle.setproctitle(new_proctitle)
        def signal_handler(_signal, frame):
            if _signal != 15:
                if _signal != 2:
                    return
            # Cleanup IPC stuff.
            multiprocessing.cleanup()
            # Finally exit.
            os._exit(0)
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)
        while True:
            if config.daemon_shutdown:
                os._exit(0)
            multiprocessing.cluster_out_event.wait()
            if config.two_node_setup:
                multiprocessing.two_node_setup_event.set()
                multiprocessing.two_node_setup_event.close()
            for node_name in multiprocessing.node_connections:
                conn_even_name = self.get_conn_event_name(node_name)
                conn_event = multiprocessing.Event(conn_even_name)
                conn_event.set()
                conn_event.close()

    def get_master_node(self, quiet=False):
        """ Get master node. """
        node_fails = {}
        node_votes = {}

        while True:
            if config.daemon_shutdown:
                os._exit(0)
            enabled_nodes = list(self.get_enabled_nodes())
            try:
                master_node = multiprocessing.master_node['master']
            except KeyError:
                master_node = None
            if master_node:
                enabled_nodes.remove(master_node)
                enabled_nodes.append(master_node)
            for node_name in enabled_nodes:
                if node_name == self.host_name:
                    node_vote = calc_node_vote()
                    node_votes[self.host_name] = node_vote
                    continue
                try:
                    clusterd_conn = self.get_clusterd_connection(node_name)
                except Exception as e:
                    self.node_disconnect(node_name)
                    try:
                        node_fails[node_name] += 1
                    except:
                        node_fails[node_name] = 1
                    #msg = ("Failed to get master node election connection: %s: %s"
                    #        % (node_name, e))
                    #self.logger.warning(msg)
                    try:
                        node_votes.pop(node_name)
                    except KeyError:
                        pass
                    time.sleep(1)
                    continue
                try:
                    x_node_vote = clusterd_conn.get_node_vote()
                except Exception as e:
                    self.node_disconnect(node_name)
                    msg = ("Failed to get cluster vote: %s: %s"
                            % (node_name, e))
                    self.logger.warning(msg)
                    x_node_vote = None
                if x_node_vote is None or x_node_vote == 0:
                    try:
                        node_votes.pop(node_name)
                    except KeyError:
                        pass
                    continue
                if config.debug_level() > 2:
                    if not quiet:
                        msg = ("Got cluster vote from node: %s: %s"
                                % (node_name, x_node_vote))
                        self.logger.debug(msg)
                node_votes[node_name] = x_node_vote

            conn_tries_done = True
            for x_node in multiprocessing.online_nodes:
                if x_node in node_votes:
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
            break

        node_revisions = []
        _node_votes = node_votes.copy()
        for x in _node_votes:
            node_revision = _node_votes[x]['revision']
            node_revisions.append(node_revision)

        try:
            master_node = multiprocessing.master_node['master']
        except KeyError:
            master_node = None
        if not master_node:
            if len(set(node_revisions)) > 1:
                highest_revision = sorted(node_revisions)[-1]
                for x in dict(_node_votes):
                    node_revision = _node_votes[x]['revision']
                    if node_revision == highest_revision:
                        continue
                    _node_votes.pop(x)

        x_sort = lambda x: _node_votes[x]['vote']
        node_scores_sorted = sorted(_node_votes, key=x_sort, reverse=True)
        new_master_node = node_scores_sorted[0]

        return new_master_node, node_votes

    def do_master_node_election(self):
        """ Do master node election. """
        # Get new master node.
        new_master_node, node_scores = self.get_master_node()

        try:
            old_master_node = multiprocessing.master_node['master']
        except KeyError:
            old_master_node = None
        if old_master_node != new_master_node:
            node_name = config.host_data['name']
            if new_master_node == node_name:
                sync_time = time.time()
                config.touch_node_sync_file(sync_time)
            self.logger.info("Node votes: %s" % node_scores)
            print("New master node: %s" % new_master_node)

            import pprint
            pprint.pprint(node_scores)

        required_votes = self.calc_quorum()[1]
        if len(node_scores) >= required_votes:
            return new_master_node
        msg = "Master node election failed: Not enough votes"
        for x in node_scores:
            msg = "%s: %s" % (msg, x)
        raise MasterNodeElectionFailed(msg)

    def get_enabled_nodes(self):
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
        for node in result:
            if not node.enabled:
                continue
            enabled_nodes[node.name] = node
        return enabled_nodes

    def calc_quorum(self):
        """ Calculate cluster quorum. """
        # Get enabled nodes.
        enabled_nodes = self.get_enabled_nodes()
        # We need at least half of the enabled nodes to gain quorum.
        required_votes = len(enabled_nodes) / 2

        quorum = False
        try:
            master_node_candidate = self.get_master_node(quiet=True)[0]
        except MasterNodeElectionFailed as e:
            self.logger.critical(e)
            current_votes = 1
            return current_votes, required_votes, quorum

        # Get current (active) node votes including own node.
        current_votes = 0
        node_vote_data = calc_node_vote()
        node_vote = node_vote_data['vote']
        if node_vote > 0:
            current_votes = 1
        for node_name in multiprocessing.online_nodes:
            try:
                clusterd_conn = self.get_clusterd_connection(node_name)
            except Exception:
                self.node_disconnect(node_name)
                continue

            if node_name != master_node_candidate:
                try:
                    if not clusterd_conn.get_master_sync_status():
                        continue
                except Exception as e:
                    self.node_disconnect(node_name)
                    msg = ("Failed to get master sync status: %s: %s"
                            % (node_name, e))
                    self.logger.warning(msg)
                    continue

            try:
                x_node_vote = clusterd_conn.get_node_vote()
            except Exception as e:
                self.node_disconnect(node_name)
                msg = ("Failed to get cluster node vote: %s: %s"
                        % (node_name, e))
                self.logger.warning(msg)
                continue
            if x_node_vote == 0:
                continue

            current_votes += 1

        if current_votes >= required_votes:
            quorum = True

        # Set global quorum.
        config.cluster_quorum = quorum
        multiprocessing.cluster_quorum['quorum'] = current_votes
        # Check if we have enough member nodes.
        member_nodes_count = len(multiprocessing.member_nodes) + 1
        if member_nodes_count < required_votes:
            config.cluster_status = False
        else:
            if os.path.exists(config.node_sync_file):
                config.cluster_status = True

        return current_votes, required_votes, quorum

    def set_node_setup(self):
        """ Set node setup parameters. """
        search_attrs = {
                        'uuid'      : {'value':"*"},
                        'enabled'   : {'value':True},
                    }
        enabled_nodes = backend.search(object_type="node",
                                    attributes=search_attrs,
                                    realm=config.realm,
                                    site=config.site,
                                    return_type="name")

        if len(enabled_nodes) == 1:
            config.one_node_setup = True
            config.two_node_setup = False
        elif len(enabled_nodes) == 2:
            config.one_node_setup = False
            config.two_node_setup = True
        else:
            config.one_node_setup = False
            config.two_node_setup = False

    def handle_node_connections(self):
        """ Handle node connections. """
        # Set node setup.
        self.set_node_setup()

        if config.two_node_setup:
            if not self.two_node_handler_child:
                self.two_node_handler_child = multiprocessing.start_process(name=self.name,
                                                target=self.start_two_node_handler)
        else:
            if self.two_node_handler_child:
                self.two_node_handler_child.terminate()
                self.two_node_handler_child.join()
                self.two_node_handler_child = None

        # Make sure left over events are handled.
        if config.one_node_setup:
            self.clean_cluster_out_journal()

        # Get all nodes.
        result = backend.search(object_type="node",
                            attribute="uuid",
                            value="*",
                            realm=config.realm,
                            site=config.site,
                            return_type="instance")
        all_nodes = {}
        enabled_nodes = {}
        for node in result:
            if node.uuid == config.uuid:
                continue
            all_nodes[node.name] = node
            if not node.enabled:
                continue
            enabled_nodes[node.name] = node

        try:
            own_node = all_nodes[self.host_name]
        except KeyError:
            own_node = None
        if own_node and not own_node.enabled:
            msg = "Node disabled. Closing cluster connections."
            self.logger.warning(msg)
            if self.node_check_connections:
                self.close_node_check_connections()
            if self.node_write_connections:
                self.close_node_check_connections()
            return

        # Make sure we have a connection to all nodes.
        for node_name in enabled_nodes:
            try:
                node = enabled_nodes[node_name]
            except KeyError:
                continue
            if not node.enabled:
                continue
            if node.name == self.host_name:
                continue
            try:
                proc = self.node_check_connections[node_name]
            except:
                continue
            if proc.is_alive():
                continue
            self.close_node_check_connection(node_name)
            try:
                proc = self.node_write_connections[node_name]
            except:
                continue
            if proc.is_alive():
                continue
            self.close_node_write_connection(node_name)
            try:
                multiprocessing.node_connections.pop(node_name)
            except KeyError:
                pass

        for node_name in enabled_nodes:
            try:
                node = enabled_nodes[node_name]
            except KeyError:
                continue
            if not node.enabled:
                continue
            if node.name == self.host_name:
                continue
            if node.name not in self.node_check_connections:
                proc = multiprocessing.start_process(name=self.name,
                                            target=self.start_node_check_connection,
                                            target_args=(node.name,))
                self.node_check_connections[node.name] = proc
            if node.name not in self.node_write_connections:
                proc = multiprocessing.start_process(name=self.name,
                                            target=self.start_node_write_connection,
                                            target_args=(node.name,))
                self.node_write_connections[node.name] = proc
            multiprocessing.node_connections[node.name] = True
        # Remove connection to e.g. disabled nodes.
        for node_name in dict(self.node_check_connections):
            try:
                node = enabled_nodes[node_name]
            except KeyError:
                node = None
            if node and node.enabled:
                continue
            self.close_node_check_connection(node_name)
            self.node_leave(node_name)
            try:
                multiprocessing.node_connections.pop(node_name)
            except KeyError:
                pass
        for node_name in dict(self.node_write_connections):
            try:
                node = enabled_nodes[node_name]
            except KeyError:
                node = None
            if node and node.enabled:
                continue
            self.close_node_write_connection(node_name)
            self.node_leave(node_name)
            try:
                multiprocessing.node_connections.pop(node_name)
            except KeyError:
                pass
        # Remove nodes not active anymore (e.g. deleted).
        for node_name in enabled_nodes:
            if node_name in self.node_check_connections:
                continue
            if node_name in self.node_write_connections:
                continue
            self.node_leave(node_name)
            try:
                multiprocessing.node_connections.pop(node_name)
            except KeyError:
                pass

    def switch_master_node(self, current_master_node, new_master_node):
        """ Switch master node. """
        multiprocessing.master_node['master'] = new_master_node
        if new_master_node == self.host_name:
            msg = "Sending request to configure floating IP."
            self.logger.info(msg)
            self.comm_handler.send("controld", command="configure_floating_ip")
        elif current_master_node == self.host_name:
            msg = "Sending request to deconfigure floating IP."
            self.logger.info(msg)
            self.comm_handler.send("controld", command="deconfigure_floating_ip")
        else:
            config.master_failover = False

        if current_master_node != new_master_node:
            msg = ("Master node elected: %s" % new_master_node)
            self.logger.info(msg)

        if new_master_node == self.host_name:
            return

        if current_master_node is not None:
            return

        if new_master_node is None:
            return

        self.wait_for_master_node_failover(new_master_node)

    def wait_for_master_node_failover(self, master_node):
        """ Wait for master node to finish failover. """
        # Wait for master node to finish failover.
        max_tries = 3
        current_try = 0
        while True:
            if config.daemon_shutdown:
                os._exit(0)
            try:
                clusterd_conn = self.get_clusterd_connection(master_node)
            except Exception as e:
                self.node_disconnect(master_node)
                msg = ("Error getting cluster connection: %s: %s"
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
            try:
                master_failover_status = clusterd_conn.get_master_failover_status()
            except Exception as e:
                self.node_disconnect(master_node)
                msg = "Failed to get master failover status: %s" % e
                self.logger.warning(msg)
                continue
            if not master_failover_status:
                break
            time.sleep(1)

    def get_clusterd_connection(self, node_name, timeout=None, quiet=True):
        socket_uri = stuff.get_daemon_socket("clusterd", node_name)
        clusterd_conn = connections.get("clusterd",
                                        timeout=timeout,
                                        socket_uri=socket_uri,
                                        quiet_autoconnect=quiet,
                                        compress_request=False)
        return clusterd_conn

    def get_node_connection(self, node_name, quiet=False):
        if self.node_conn:
            try:
                self.node_conn.ping()
            except (ConnectionTimeout, ConnectionError, ConnectionQuit):
                self.node_disconnect(node_name)
            except Exception as e:
                self.node_disconnect(node_name)
                msg = ("Failed to send ping command: %s: %s"
                        % (node_name, e))
            else:
                return self.node_conn

        if self.node_conn is None:
            try:
                self.node_conn = self.get_clusterd_connection(node_name)
            except Exception as e:
                if not self.node_offline:
                    if not quiet:
                        msg = ("Failed to get cluster connection: %s: %s"
                                % (node_name, e))
                        self.logger.warning(msg)
                    self.node_leave(node_name)
                    self.node_offline = True
                return None
            else:
                multiprocessing.online_nodes[node_name] = True
                if self.node_offline:
                    if not quiet:
                        msg = "Node is online: %s" % node_name
                        self.logger.info(msg)
                    self.node_offline = False
                return self.node_conn

    def do_node_check(self, node_name):
        node_conn = self.get_node_connection(node_name)
        if not node_conn:
            return False

        if self.host_name not in multiprocessing.master_sync_done:
            return False

        try:
            current_master_node = multiprocessing.master_node['master']
        except KeyError:
            return False

        if current_master_node != node_name:
            try:
                if not self.node_conn.get_master_sync_status():
                    msg = "Waiting for node to finish master sync: %s" % node_name
                    #print(msg)
                    self.logger.info(msg)
                    return False
            except Exception as e:
                self.node_disconnect(node_name)
                msg = "Failed to get master sync status: %s: %s" % (node_name, e)
                self.logger.critical(msg)
                return False

        # Node should join the cluster.
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

        msg = ("Starting initial sync with master node: %s"
                % master_node)
        self.logger.info(msg)
        max_tries = 3
        current_try = 0
        command_handler = CommandHandler()
        while True:
            if config.daemon_shutdown:
                os._exit(0)
            skip_deletions = True
            if os.path.exists(config.node_joined_file):
                skip_deletions = False
            try:
                sync_status = command_handler.do_sync(sync_type="objects",
                                                    realm=config.realm,
                                                    site=config.site,
                                                    max_tries=10,
                                                    #ignore_changed_objects=True,
                                                    skip_object_deletion=skip_deletions,
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
                    return sync_status
                time.sleep(1)
                continue
            filetools.delete(config.node_joined_file)
            msg = "Initial sync with master node finished."
            self.logger.info(msg)
            break
        return sync_status

    def start_cluster_communication(self, **kwargs):
        """ Start cluster communication. """
        try:
            self._start_cluster_communication(**kwargs)
        except Exception as e:
            msg = "Error in cluster communication method: %s" % e
            self.logger.critical(msg)
            #config.raise_exception()

    def _start_cluster_communication(self, reload=False):
        """ Start cluster communication. """
        # Set proctitle.
        new_proctitle = "%s (Cluster communication)" % self.full_name
        setproctitle.setproctitle(new_proctitle)
        def signal_handler(_signal, frame):
            if _signal != 15:
                if _signal != 2:
                    return
            # Close all cluster connections.
            self.close_node_check_connections()
            self.close_node_write_connections()
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

        if not reload:
            multiprocessing.master_node.clear()
            multiprocessing.radius_reload_queue.clear()
            multiprocessing.nsscache_sync_queue.clear()
            multiprocessing.daemon_reload_queue.clear()
            multiprocessing.master_sync_done.clear()

        config.cluster_status = False
        config.cluster_vote_participation = True

        quorum_check_interval = 3
        quorum_message_sent = False
        wait_for_second_node = True
        second_node_wait_timeout = 0
        while True:
            if config.daemon_shutdown:
                os._exit(0)
            # Handle node connections.
            self.handle_node_connections()

            if self.host_name not in multiprocessing.master_sync_done:
                try:
                    master_node = self.get_master_node(quiet=True)[0]
                except MasterNodeElectionFailed as e:
                    self.logger.critical(e)
                    time.sleep(quorum_check_interval)
                    continue
                if master_node == self.host_name:
                    multiprocessing.master_sync_done.append(self.host_name)
                else:
                    try:
                        clusterd_conn = self.get_clusterd_connection(master_node)
                    except Exception as e:
                        msg = ("Failed to get master node connection: %s: %s"
                                % (master_node, e))
                        self.logger.warning(msg)
                        time.sleep(1)
                        continue
                    try:
                        clusterd_conn.set_node_online()
                    except Exception as e:
                        msg = ("Failed to set node online on master node: %s: %s"
                                % (master_node, e))
                        self.logger.warning(msg)
                        time.sleep(1)
                        continue
                    try:
                        remote_data_revision = clusterd_conn.get_data_revision()
                    except Exception as e:
                        msg = "Failed to get data revision: %s: %s" % (master_node, e)
                        self.logger.warning(msg)
                        time.sleep(1)
                        continue
                    local_data_revision = config.get_data_revision()
                    if remote_data_revision >= local_data_revision:
                        while True:
                            cluster_journal_files = self.get_cluster_in_journal()
                            if cluster_journal_files:
                                multiprocessing.cluster_in_event.set()
                                time.sleep(1)
                                continue
                            break
                        self.do_master_node_sync(master_node)
                        sync_status = self.do_master_node_sync(master_node)
                        if sync_status is False:
                            continue
                        if self.host_name not in multiprocessing.master_sync_done:
                            multiprocessing.master_sync_done.append(self.host_name)
                    else:
                        multiprocessing.master_sync_done.append(self.host_name)
                    # Start initial data sync.
                    self.start_initial_sync(master_node)

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

            if not quorum:
                if config.start_freeradius:
                    self.stop_freeradius()
                try:
                    current_master_node = multiprocessing.master_node['master']
                except KeyError:
                    current_master_node = None
                try:
                    self.switch_master_node(current_master_node=current_master_node,
                                            new_master_node=None)
                except Exception as e:
                    msg = "Failed to switch master node: %s" % e
                    self.logger.critical(msg)
                time.sleep(quorum_check_interval)
                continue

            # For two node clusters wait for second node to appear.
            do_master_node_election = True
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

            if config.start_freeradius:
                if config.cluster_status:
                    if not config.daemon_shutdown:
                        self.start_freeradius()

            try:
                current_master_node = multiprocessing.master_node['master']
            except KeyError:
                current_master_node = None
            if current_master_node == new_master_node:
                time.sleep(quorum_check_interval)
                continue

            while True:
                cluster_journal_files = self.get_cluster_in_journal()
                if not cluster_journal_files:
                    break
                msg = "Waiting for cluster in journal to be processed..."
                self.logger.info(msg)
                time.sleep(1)

            try:
                self.switch_master_node(current_master_node, new_master_node)
            except Exception as e:
                msg = "Failed to switch master node: %s" % e
                self.logger.critical(msg)

            time.sleep(quorum_check_interval)

    def handle_two_node_setup(self):
        # Two node setups require some special handling if second node is down.
        if not config.two_node_setup:
            return
        if len(multiprocessing.member_nodes) > 0:
            return
        all_entries = self.get_cluster_out_journal()
        cluster_journal_dirs = list(set(all_entries) - set(self.processed_journal_entries))
        for journal_entry in cluster_journal_dirs:
            entry_timestamp = os.path.basename(journal_entry)
            cluster_journal_entry = ClusterJournalEntry(timestamp=entry_timestamp)
            try:
                if not cluster_journal_entry.committed:
                    continue
                if not self.check_member_nodes(cluster_journal_entry):
                    continue
                self.check_online_nodes(cluster_journal_entry)
            except ObjectDeleted:
                pass
            except ProcessingFailed:
                return
        outdated_entries = set(self.processed_journal_entries) - set(all_entries)
        self.processed_journal_entries = list(set(self.processed_journal_entries) - outdated_entries)

    def set_node_online(self, node_name):
        """ Set node online. """
        # Check if node is online. If connections was broken
        # peer_nodes_set_online will be cleared.
        node_conn = self.get_node_connection(node_name)
        if not node_conn:
            return False
        if node_name in multiprocessing.peer_nodes_set_online:
            return True
        msg = "Setting node online status: %s" % node_name
        self.logger.info(msg)
        try:
            self.node_conn.set_node_online()
        except Exception as e:
            self.node_disconnect(node_name)
            msg = ("Failed to set node online status: %s: %s"
                    % (node_name, e))
            self.logger.warning(msg)
            return False
        else:
            multiprocessing.peer_nodes_set_online[node_name] = True
        return True

    def start_in_journal_handler(self):
        """ Start cluster in journal handler. """
        # Set proctitle.
        new_proctitle = ("%s Cluster in-journal" % self.full_name)
        setproctitle.setproctitle(new_proctitle)

        def signal_handler(_signal, frame):
            if _signal != 15:
                if _signal != 2:
                    return
            # Cleanup IPC stuff.
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
        while True:
            try:
                multiprocessing.cluster_in_event.wait(timeout=3)
            except TimeoutReached:
                pass
            finally:
                multiprocessing.cluster_in_event.close()

            if config.daemon_shutdown:
                os._exit(0)

            try:
                self.handle_cluster_in_journal()
            except Exception as e:
                msg = "Failed to handle cluster in journal: %s" % e
                self.logger.critical(msg)
                #config.raise_exception()

    def handle_cluster_in_journal(self):
        cluster_journal_files = self.get_cluster_in_journal()
        for journal_file in cluster_journal_files:
            object_data = filetools.read_file(path=journal_file,
                                            compression="lz4")
            object_data = ujson.loads(object_data)

            action = object_data['action']
            if action == "write":
                object_id = object_data['object_id']
                object_id = oid.get(object_id)
                last_used = object_data['last_used']
                full_data_update = object_data['full_data_update']
                full_index_update = object_data['full_index_update']
                index_journal = object_data['index_journal']
                object_config = object_data['object_config']
                object_config = ObjectConfig(object_id, object_config)
                object_config = object_config.decrypt(config.master_key)
                object_uuid = object_config['UUID']

                x_object = backend.get_object(object_id)
                if x_object:
                    x_object.acquire_lock(lock_caller="cluster")
                try:
                    if last_used is not None:
                        backend.set_last_used(object_id.realm,
                                            object_id.site,
                                            object_id.object_type,
                                            object_uuid, last_used)
                    try:
                        backend.write_config(object_id=object_id,
                                            cluster=False,
                                            full_data_update=full_data_update,
                                            full_index_update=full_index_update,
                                            index_journal=index_journal,
                                            object_config=object_config)
                    except Exception as e:
                        msg = "Failed to write object: %s: %s" % (object_id, e)
                        self.logger.warning(msg)
                        #config.raise_exception()
                        continue
                finally:
                    if x_object:
                        x_object.release_lock(lock_caller="cluster")

                # Update signers cache.
                if object_id.object_type != "user":
                    try:
                        os.remove(journal_file)
                    except Exception as e:
                        msg = ("Failed to delete cluster in journal file: %s: %s"
                                % (journal_file, e))
                        self.logger.critical(msg)
                    continue

                # Load instance.
                try:
                    new_object = backend.get_object(object_id)
                except Exception as e:
                    msg = "Failed to load new object: %s: %s" % (object_id, e)
                    self.logger.critical(msg)
                    continue

                if not new_object.public_key:
                    try:
                        os.remove(journal_file)
                    except Exception as e:
                        msg = ("Failed to delete cluster in journal file: %s: %s"
                                % (journal_file, e))
                        self.logger.critical(msg)
                    continue

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

            if action == "rename":
                object_id = object_data['object_id']
                object_id = oid.get(object_id)
                new_object_id = object_data['new_object_id']
                new_object_id = oid.get(new_object_id)
                our_object = backend.get_object(object_id)
                if our_object.oid.full_oid == object_id.full_oid:
                    msg = "Renaming object: %s: %s" % (object_id, new_object_id)
                    self.logger.debug(msg)
                    try:
                        backend.rename_object(object_id,
                                            new_object_id,
                                            cluster=False)
                    except Exception as e:
                        msg = "Failed to rename object: %s: %s" % (object_id, e)
                        self.logger.warning(msg)

            if action == "delete":
                object_id = object_data['object_id']
                object_id = oid.get(object_id)
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
                try:
                    backend.delete_object(object_id=object_id)
                except UnknownObject:
                    pass
                except Exception as e:
                    msg = "Failed to delete object: %s: %s" % (object_id, e)
                    self.logger.warning(msg)
                else:
                    msg = "Removed object: %s" % object_id
                    self.logger.debug(msg)

            try:
                os.remove(journal_file)
            except Exception as e:
                msg = ("Failed to delete cluster in journal file: %s: %s"
                        % (journal_file, e))
                self.logger.critical(msg)

    def start_two_node_handler(self):
        try:
            self._start_two_node_handler()
        except Exception as e:
            msg = "Error in two node handler: %s" % e
            self.logger.critical(msg)
            #config.raise_exception()

    def _start_two_node_handler(self):
        """ Start two node handler. """
        # Set proctitle.
        new_proctitle = ("%s Cluster two node handler" % (self.full_name))
        setproctitle.setproctitle(new_proctitle)

        def signal_handler(_signal, frame):
            if _signal != 15:
                if _signal != 2:
                    return
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
        while True:
            multiprocessing.two_node_setup_event.wait()

            if config.daemon_shutdown:
                os._exit(0)

            self.handle_two_node_setup()

    def start_node_check_connection(self, node_name):
        """ Start cluster communication with node. """
        # Set proctitle.
        new_proctitle = ("%s Cluster node check (%s)"
                        % (self.full_name, node_name))
        setproctitle.setproctitle(new_proctitle)

        def signal_handler(_signal, frame):
            if _signal != 15:
                if _signal != 2:
                    return
            # Cleanup IPC stuff.
            if self.node_conn:
                self.node_conn.close()
            multiprocessing.cleanup()
            os._exit(0)
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)

        self.node_name = node_name

        # Update logger with new PID and daemon name.
        self.pid = os.getpid()
        log_banner = "%s:" % self.full_name
        self.logger = config.setup_logger(banner=log_banner,
                                        pid=self.pid,
                                        existing_logger=config.logger)
        while True:
            if config.daemon_shutdown:
                os._exit(0)

            time.sleep(1)

            # Mark node as online on peer node.
            if not self.set_node_online(node_name):
                continue

            do_node_check = False
            if node_name not in multiprocessing.member_nodes:
                do_node_check = True

            if do_node_check:
                if not self.do_node_check(node_name):
                    try:
                        multiprocessing.ready_nodes.pop(node_name)
                    except KeyError:
                        pass
                    continue

            multiprocessing.ready_nodes[node_name] = True

            if node_name not in multiprocessing.online_nodes:
                continue

            try:
                self.handle_nsscache_sync(node_name)
            except Exception as e:
                msg = "nsscache sync request failed: %s" % e
                self.logger.critical(msg)

            try:
                self.handle_radius_reload(node_name)
            except Exception as e:
                msg = "Radius reload request failed: %s" % e
                self.logger.critical(msg)

            try:
                self.handle_daemon_reload(node_name)
            except Exception as e:
                msg = "Radius reload request failed: %s" % e
                self.logger.critical(msg)

    def start_node_write_connection(self, node_name):
        try:
            self._start_node_write_connection(node_name)
        except Exception as e:
            msg = "Error in node write connection: %s" % e
            self.logger.critical(msg)
            #config.raise_exception()

    def _start_node_write_connection(self, node_name):
        """ Start cluster write communication with node. """
        # Set proctitle.
        new_proctitle = ("%s Cluster sync (%s)"
                        % (self.full_name, node_name))
        setproctitle.setproctitle(new_proctitle)

        conn_even_name = self.get_conn_event_name(node_name)
        self.conn_event = multiprocessing.Event(conn_even_name)

        def signal_handler(_signal, frame):
            if _signal != 15:
                if _signal != 2:
                    return
            # Cleanup IPC stuff.
            if self.node_conn:
                self.node_conn.close()
            self.conn_event.unlink()
            multiprocessing.cleanup()
            os._exit(0)
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)

        self.node_name = node_name
        self.member_candidate_dir = os.path.join(config.member_candidate_dir,
                                                node_name)
        if not os.path.exists(self.member_candidate_dir):
            filetools.create_dir(self.member_candidate_dir)

        # Update logger with new PID and daemon name.
        self.pid = os.getpid()
        log_banner = "%s:" % self.full_name
        self.logger = config.setup_logger(banner=log_banner,
                                        pid=self.pid,
                                        existing_logger=config.logger)
        start_over= True
        while True:
            # Wait for cluster event.
            event_timeout = 3
            if start_over:
                event_timeout = 0.01
            try:
                self.conn_event.wait(timeout=event_timeout)
            except TimeoutReached:
                pass
            #finally:
            #    self.conn_event.close()

            if config.daemon_shutdown:
                os._exit(0)

            if self.node_conn is None:
                node_conn = self.get_node_connection(node_name)
                if not node_conn:
                    continue

            start_over= False
            if node_name not in multiprocessing.ready_nodes:
                start_over = True
                continue
            if node_name not in multiprocessing.online_nodes:
                start_over = True
                continue

            try:
                start_over = self.handle_cluster_out_journal(node_name)
            except Exception as e:
                start_over = True
                msg = "Failed to handle cluster journal: %s" % e
                self.logger.critical(msg)
                #print(msg)
                #config.raise_exception()

    def handle_cluster_out_journal(self, node_name):
        while True:
            try:
                written_entries = self.process_cluster_journal(node_name)
            except ProcessingFailed:
                return True
            except Exception as e:
                msg = "Error processing cluster journal: %s" % e
                self.logger.critical(msg)
                #config.raise_exception()
                return True
            if not self.member_candidate:
                break
            if len(written_entries) <= 10:
                break
        if self.member_candidate:
            multiprocessing.pause_writes.append(self.pid)
            try:
                try:
                    self.process_cluster_journal(node_name)
                except ProcessingFailed:
                    return True
                except Exception as e:
                    msg = "Error processing cluster journal: %s" % e
                    self.logger.critical(msg)
                    #config.raise_exception()
                    return True
                # Update data revision on peer.
                if config.master_node:
                    try:
                        remote_data_revision = self.node_conn.get_data_revision()
                    except Exception as e:
                        msg = "Failed to get data revision: %s: %s" % (node_name, e)
                        raise OTPmeException(msg)
                    local_data_revision = config.get_data_revision()
                    if remote_data_revision < local_data_revision:
                        result = backend.search(object_type="data_revision",
                                                attribute="uuid",
                                                value="*",
                                                return_type="oid")
                        if result:
                            object_id = result[0]
                            object_config = backend.read_config(object_id)
                            object_config = object_config.copy()
                            object_uuid = object_config['UUID']
                            try:
                                last_used = backend.get_last_used(object_id.realm,
                                                                object_id.site,
                                                                object_id.object_type,
                                                                object_uuid)
                            except Exception as e:
                                msg = ("Failed to get last used time: %s: %s"
                                        % (object_id, e))
                                self.logger.warning(msg)
                                raise OTPmeException(msg)
                            try:
                                self.node_conn.write(object_id.full_oid,
                                                    object_config,
                                                    last_used,
                                                    full_data_update=True,
                                                    full_index_update=True)
                            except (ConnectionTimeout, ConnectionError, ConnectionQuit) as e:
                                self.node_disconnect(node_name)
                                msg = ("Failed to send object: %s: %s: %s"
                                        % (node_name, object_id, e))
                                self.logger.warning(msg)
                                raise OTPmeException(msg)
                            except Exception as e:
                                self.node_disconnect(node_name)
                                msg = ("Error sending object: %s: %s: %s"
                                        % (node_name, object_id, e))
                                self.logger.warning(msg)
                                raise OTPmeException(msg)
            finally:
                multiprocessing.pause_writes.remove(self.pid)

            # Add node to cluster member nodes.
            self.member_candidate = False
            multiprocessing.member_nodes[node_name] = True
            msg = "Node joined the cluster: %s" % node_name
            self.logger.info(msg)

        try:
            entries_to_process = self.get_journal_entries_to_process(node_name)
        except ProcessingFailed:
            return True
        if entries_to_process:
            return True

    def get_journal_entries_to_process(self, node_name):
        entries_to_process = []
        all_entries = self.get_cluster_out_journal()
        cluster_journal_dirs = list(set(all_entries) - set(self.processed_journal_entries))
        for journal_dir in cluster_journal_dirs:
            entry_timestamp = os.path.basename(journal_dir)
            cluster_journal_entry = ClusterJournalEntry(timestamp=entry_timestamp)
            try:
                if not cluster_journal_entry.committed:
                    break
                if node_name in cluster_journal_entry.get_nodes():
                    # Check if object was written to member nodes.
                    if self.check_member_nodes(cluster_journal_entry):
                        # Check if object was written to all online nodes.
                        self.check_online_nodes(cluster_journal_entry)
                    continue
                entries_to_process.append(cluster_journal_entry)
            except ObjectDeleted:
                pass
        outdated_entries = set(self.processed_journal_entries) - set(all_entries)
        self.processed_journal_entries = list(set(self.processed_journal_entries) - outdated_entries)
        return sorted(entries_to_process)

    def process_cluster_journal(self, node_name):
        """ Process cluster journal. """
        entries_to_process = self.get_journal_entries_to_process(node_name)
        if entries_to_process:
            msg = "Handling cluster out journal: %s" % node_name
            self.logger.debug(msg)
        written_entries = []
        full_written_objects = {}
        unsync_status_set = False
        for cluster_journal_entry in entries_to_process:
            node_conn = self.node_conn
            if node_conn is None:
                msg = "No node connection."
                raise ProcessingFailed(msg)
            try:
                object_id = cluster_journal_entry.object_id
                object_id = oid.get(object_id)
                object_uuid = cluster_journal_entry.object_uuid
                object_checksum = cluster_journal_entry.object_checksum
                # We need to read action last because it will throw
                # ObjectDeleted exception if the cluster entry was deleted.
                action = cluster_journal_entry.action

                # Mark node as out of sync (tree objects).
                if config.master_node:
                    if object_id.object_type in config.tree_object_types:
                        if not unsync_status_set:
                            unsync_status_set = True
                            try:
                                self.unset_node_sync(node_name)
                            except:
                                self.check_member_nodes(cluster_journal_entry)
                                raise ProcessingFailed()
                # Write object to peer.
                if action == "write":
                    object_config = cluster_journal_entry.object_config
                    # Remove outdated cluster journal entry.
                    if not object_config:
                        cluster_journal_entry.add_node(node_name)
                        if self.check_member_nodes(cluster_journal_entry):
                            self.check_online_nodes(cluster_journal_entry)
                        continue
                    full_data_update = False
                    full_index_update = False
                    full_object_update = False
                    if self.member_candidate:
                        oc = None
                        if object_id in full_written_objects:
                            oc = backend.read_config(object_id)
                            if oc:
                                sync_checksum = oc['SYNC_CHECKSUM']
                                cached_sync_checksum = full_written_objects[object_id]
                                if sync_checksum == cached_sync_checksum:
                                    cluster_journal_entry.add_node(node_name)
                                    if self.check_member_nodes(cluster_journal_entry):
                                        self.check_online_nodes(cluster_journal_entry)
                                    continue
                        if not oc:
                            oc = backend.read_config(object_id)
                        if oc:
                            full_data_update = True
                            full_index_update = True
                            full_object_update = True
                            object_config = oc.copy()
                    index_journal = []
                    if not full_index_update:
                        index_journal = cluster_journal_entry.index_journal
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
                        write_status = node_conn.write(object_id.full_oid,
                                                        object_config,
                                                        last_used,
                                                        index_journal=index_journal,
                                                        #full_data_update=True,
                                                        full_data_update=full_data_update,
                                                        #full_index_update=True)
                                                        full_index_update=full_index_update)
                    except (ConnectionTimeout, ConnectionError, ConnectionQuit) as e:
                        self.node_leave(node_name)
                        msg = ("Failed to send object: %s: %s: %s"
                                % (node_name, object_id, e))
                        self.logger.warning(msg)
                        self.check_member_nodes(cluster_journal_entry)
                        raise ProcessingFailed(msg)
                    except Exception as e:
                        self.node_leave(node_name)
                        msg = ("Error sending object: %s: %s: %s"
                                % (node_name, object_id, e))
                        self.logger.warning(msg)
                        self.check_member_nodes(cluster_journal_entry)
                        raise ProcessingFailed(msg)
                    if write_status != "done":
                        continue
                    msg = ("Written object to node: %s: %s (%s)"
                            % (node_name, object_id, object_checksum))
                    self.logger.debug(msg)
                    cluster_journal_entry.add_node(node_name)
                    written_entries.append(object_id)
                    if full_object_update:
                        sync_checksum = object_config['SYNC_CHECKSUM']
                        full_written_objects[object_id] = sync_checksum
                # Rename object on peer.
                if action == "rename":
                    new_object_id = cluster_journal_entry.new_object_id
                    new_object_id = oid.get(new_object_id)
                    try:
                        rename_status = node_conn.rename(object_id=object_id.full_oid,
                                                        new_object_id=new_object_id.full_oid)
                    except (ConnectionTimeout, ConnectionError, ConnectionQuit) as e:
                        self.node_leave(node_name)
                        msg = ("Failed to rename object: %s: %s: %s"
                                % (node_name, object_id, e))
                        self.logger.warning(msg)
                        self.check_member_nodes(cluster_journal_entry)
                        raise ProcessingFailed(msg)
                    except Exception as e:
                        self.node_leave(node_name)
                        msg = ("Failed to rename object: %s: %s: %s"
                                % (node_name, object_id, e))
                        self.logger.warning(msg)
                        self.check_member_nodes(cluster_journal_entry)
                        raise ProcessingFailed(msg)
                    if rename_status != "done":
                        continue
                    msg = ("Renamed object on node: %s: %s: %s"
                            % (node_name, object_id, new_object_id))
                    self.logger.debug(msg)
                    cluster_journal_entry.add_node(node_name)
                # Delete object on peer.
                if action == "delete":
                    try:
                        del_status = node_conn.delete(object_id.full_oid)
                    except (ConnectionTimeout, ConnectionError, ConnectionQuit) as e:
                        self.node_leave(node_name)
                        msg = "Failed to delete object: %s: %s" % (object_id, e)
                        self.logger.warning(msg)
                        self.check_member_nodes(cluster_journal_entry)
                        raise ProcessingFailed(msg)
                    except Exception as e:
                        self.node_leave(node_name)
                        msg = "Failed to delete object: %s: %s" % (object_id, e)
                        self.logger.warning(msg)
                        self.check_member_nodes(cluster_journal_entry)
                        raise ProcessingFailed(msg)
                    if del_status != "done":
                        continue
                    msg = ("Deleted object on node: %s: %s"
                            % (node_name, object_id))
                    self.logger.debug(msg)
                    try:
                        full_written_objects.pop(object_id)
                    except KeyError:
                        pass
                    cluster_journal_entry.add_node(node_name)

                # Check if object was written to member nodes.
                if self.check_member_nodes(cluster_journal_entry):
                    # Check if object was written to all online nodes.
                    self.check_online_nodes(cluster_journal_entry)
            except ObjectDeleted:
                pass

        if config.master_node:
            if not config.master_failover:
                sync_time = time.time()
                config.touch_node_sync_file(sync_time)
                # Mark node as in sync (tree objects).
                try:
                    self.set_node_sync(node_name, sync_time-300)
                except:
                    raise ProcessingFailed()
        return written_entries

    def set_node_sync(self, node_name, sync_time):
        try:
            self.node_conn.set_node_sync(sync_time)
        except (ConnectionTimeout, ConnectionError, ConnectionQuit) as e:
            self.node_disconnect(node_name)
            msg = ("Failed to set cluster sync state: %s: %s"
                    % (node_name, e))
            self.logger.warning(msg)
            raise
        except Exception as e:
            self.node_disconnect(node_name)
            msg = ("Error setting cluster sync state: %s: %s"
                    % (node_name, e))
            self.logger.warning(msg)
            raise

    def unset_node_sync(self, node_name):
        try:
            self.node_conn.unset_node_sync()
        except (ConnectionTimeout, ConnectionError, ConnectionQuit) as e:
            self.node_leave(node_name)
            msg = ("Failed to unset cluster sync state: %s: %s"
                    % (node_name, e))
            self.logger.warning(msg)
            raise
        except Exception as e:
            self.node_leave(node_name)
            msg = ("Error unsetting cluster sync state: %s: %s"
                    % (node_name, e))
            self.logger.warning(msg)
            raise

    def check_online_nodes(self, cluster_journal_entry):
        entry_nodes = cluster_journal_entry.get_nodes()
        online_nodes_in_sync = True
        for node_name in multiprocessing.online_nodes:
            if node_name in entry_nodes:
                continue
            online_nodes_in_sync = False
        if not online_nodes_in_sync:
            return
        # Delete journal entries must be synced to all nodes
        # even offline ones.
        all_nodes_in_sync = True
        if cluster_journal_entry.action == "delete":
            all_nodes = backend.search(object_type="node",
                                        attribute="uuid",
                                        value="*",
                                        realm=config.realm,
                                        site=config.site,
                                        return_type="name")
            for node_name in all_nodes:
                if node_name == self.host_name:
                    continue
                if node_name in entry_nodes:
                    continue
                all_nodes_in_sync = False
        if not all_nodes_in_sync:
            return
        object_event = get_object_event(cluster_journal_entry.timestamp)
        object_event.set()
        object_event.unlink()
        cluster_journal_entry.delete()

    def check_member_nodes(self, cluster_journal_entry):
        entry_nodes = sorted(cluster_journal_entry.get_nodes())
        member_nodes = sorted(multiprocessing.member_nodes)
        written_nodes = 0
        member_nodes_in_sync = True
        for node_name in member_nodes:
            if node_name in entry_nodes:
                written_nodes += 1
                continue
            member_nodes_in_sync = False
        if written_nodes >= 2:
            member_nodes_in_sync = True
        if not member_nodes_in_sync:
            return False
        object_event = get_object_event(cluster_journal_entry.timestamp)
        object_event.set()
        object_event.unlink()
        self.processed_journal_entries.append(cluster_journal_entry.entry_dir)
        return True

    def handle_nsscache_sync(self, node_name):
        # Handle nsscache sync requests.
        for sync_time in multiprocessing.nsscache_sync_queue:
            if node_name not in multiprocessing.member_nodes:
                continue
            sync_sent_to_all_nodes = True
            for x_node in multiprocessing.member_nodes:
                multiprocessing.nsscache_sync_queue.lock()
                try:
                    node_list = multiprocessing.nsscache_sync_queue[sync_time]
                except KeyError:
                    continue
                finally:
                    multiprocessing.nsscache_sync_queue.release()
                if x_node in node_list:
                    continue
                sync_sent_to_all_nodes = False
                break
            if sync_sent_to_all_nodes:
                multiprocessing.nsscache_sync_queue.lock()
                try:
                    multiprocessing.nsscache_sync_queue.pop(sync_time)
                except KeyError:
                    pass
                finally:
                    multiprocessing.nsscache_sync_queue.release()
                return
            try:
                node_list = multiprocessing.nsscache_sync_queue[sync_time]
            except KeyError:
                continue
            if node_name in node_list:
                continue
            multiprocessing.nsscache_sync_queue.lock()
            try:
                # Send sync request.
                try:
                    self.node_conn.do_nsscache_sync()
                except Exception as e:
                    self.node_disconnect(node_name)
                    msg = ("Failed to send nsscache sync request: %s: %s"
                            % (node_name, e))
                    self.logger.warning(msg)
                    continue
                else:
                    try:
                        node_list = multiprocessing.nsscache_sync_queue[sync_time]
                    except KeyError:
                        continue
                    node_list.append(node_name)
                    try:
                        multiprocessing.nsscache_sync_queue[sync_time] = node_list
                    except KeyError:
                        pass
                    msg = "nsscache sync request sent to node: %s" % node_name
                    self.logger.info(msg)
            finally:
                multiprocessing.nsscache_sync_queue.release()

    def handle_radius_reload(self, node_name):
        # Handle radius reload requests.
        for reload_time in multiprocessing.radius_reload_queue:
            if node_name not in multiprocessing.member_nodes:
                continue
            all_nodes_reloaded = True
            for x_node in multiprocessing.member_nodes:
                multiprocessing.radius_reload_queue.lock()
                try:
                    node_list = multiprocessing.radius_reload_queue[reload_time]
                except KeyError:
                    continue
                finally:
                    multiprocessing.radius_reload_queue.release()
                if x_node in node_list:
                    continue
                all_nodes_reloaded = False
                break
            if all_nodes_reloaded:
                multiprocessing.radius_reload_queue.lock()
                try:
                    multiprocessing.radius_reload_queue.pop(reload_time)
                except KeyError:
                    pass
                finally:
                    multiprocessing.radius_reload_queue.release()
                return
            try:
                node_list = multiprocessing.radius_reload_queue[reload_time]
            except KeyError:
                continue
            if node_name in node_list:
                continue
            # Make sure radius gets reloaded (after objects have changed.).
            multiprocessing.radius_reload_queue.lock()
            try:
                self.node_conn.do_radius_reload()
            except Exception as e:
                self.node_disconnect(node_name)
                msg = "Failed to send radius reload request: %s" % e
                self.logger.warning(msg)
                break
            else:
                try:
                    node_list = multiprocessing.radius_reload_queue[reload_time]
                except KeyError:
                    continue
                node_list.append(node_name)
                try:
                    multiprocessing.radius_reload_queue[reload_time] = node_list
                except KeyError:
                    pass
                msg = "Radius reload request sent to node: %s" % node_name
                self.logger.info(msg)
            finally:
                multiprocessing.radius_reload_queue.release()

    def handle_daemon_reload(self, node_name):
        # Handle daemon reload requests.
        for reload_time in multiprocessing.daemon_reload_queue:
            if node_name not in multiprocessing.member_nodes:
                continue
            all_nodes_reloaded = True
            for x_node in multiprocessing.member_nodes:
                multiprocessing.daemon_reload_queue.lock()
                try:
                    node_list = multiprocessing.daemon_reload_queue[reload_time]
                except KeyError:
                    continue
                finally:
                    multiprocessing.daemon_reload_queue.release()
                if x_node in node_list:
                    continue
                all_nodes_reloaded = False
                break
            if all_nodes_reloaded:
                multiprocessing.daemon_reload_queue.lock()
                try:
                    multiprocessing.daemon_reload_queue.pop(reload_time)
                except KeyError:
                    pass
                finally:
                    multiprocessing.daemon_reload_queue.release()
                # Reload ourselves.
                try:
                    self.comm_handler.send("controld", command="reload")
                except Exception as e:
                    msg = "Failed to send reload command to controld: %s" % e
                    self.logger.critical(msg)
                return
            try:
                node_list = multiprocessing.daemon_reload_queue[reload_time]
            except KeyError:
                continue
            if node_name in node_list:
                continue
            multiprocessing.daemon_reload_queue.lock()
            try:
                self.node_conn.do_daemon_reload()
            except Exception as e:
                self.node_disconnect(node_name)
                msg = "Failed to send daemon reload request: %s" % e
                self.logger.warning(msg)
                break
            else:
                try:
                    node_list = multiprocessing.daemon_reload_queue[reload_time]
                except KeyError:
                    continue
                node_list.append(node_name)
                try:
                    multiprocessing.daemon_reload_queue[reload_time] = node_list
                except KeyError:
                    pass
                msg = "Daemon reload request sent to node: %s" % node_name
                self.logger.info(msg)
            finally:
                multiprocessing.daemon_reload_queue.release()

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

    def close_node_check_connection(self, node_name):
        """ Close all node check connections. """
        proc = self.node_check_connections[node_name]
        proc.terminate()
        #stuff.wait_pid(pid=proc.pid,
        #            recursive=True)
        proc.join()
        try:
            self.node_check_connections.pop(node_name)
        except KeyError:
            pass

    def close_node_check_connections(self):
        """ Close all node check connections. """
        for node_name in list(self.node_check_connections):
            self.close_node_check_connection(node_name)

    def close_node_write_connection(self, node_name):
        """ Close all node write connections. """
        proc = self.node_write_connections[node_name]
        proc.terminate()
        #stuff.wait_pid(pid=proc.pid,
        #            recursive=True)
        proc.join()
        try:
            self.node_write_connections.pop(node_name)
        except KeyError:
            pass

    def close_node_write_connections(self):
        """ Close all node write connections. """
        for node_name in list(self.node_write_connections):
            self.close_node_write_connection(node_name)

    def _run(self, reload=False, master_node=False, **kwargs):
        """ Start daemon loop. """
        # FIXME: where to configure max_conn?
        # Set max client connections.
        self.max_conn = 100
        # Set signal handler.
        signal.signal(signal.SIGTERM, self.signal_handler)
        signal.signal(signal.SIGINT, self.signal_handler)
        # Initially we dont have quorum.
        config.cluster_quorum = False
        multiprocessing.cluster_quorum.clear()
        multiprocessing.sync_nodes.clear()
        # On daemon reload we have to keep master node status.
        if reload:
            if master_node:
                sync_time = time.time()
                config.touch_node_sync_file(sync_time)
            else:
                config.remove_node_sync_file()
        else:
            # On daemon startup we will decide by data revision which node gets master.
            config.remove_node_sync_file()
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

        # Make sure cluster in journal is clean on daemon start.
        self.clean_cluster_in_journal()

        # Set node setup.
        self.set_node_setup()

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
            msg = "Failed to send ready message to controld: %s" % e
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
        self.start_childs(reload=reload)

        while True:
            if config.daemon_shutdown:
                os._exit(0)
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

                if daemon_command is None:
                    continue
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
                if daemon_command == "ip_configured":
                    config.master_failover = False
                if daemon_command == "ip_deconfigured":
                    config.master_failover = False
            except (KeyboardInterrupt, SystemExit):
                pass
            except Exception as e:
                msg = ("Unhandled error in clusterd: %s" % e)
                self.logger.critical(msg, exc_info=True)
                #config.raise_exception()
