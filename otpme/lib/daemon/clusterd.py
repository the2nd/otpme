# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
# Distributed under the terms of the GNU General Public License v2
import os
import time
import json
import glob
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
from otpme.lib import multiprocessing
from otpme.lib.protocols import status_codes
from otpme.lib.daemon.otpme_daemon import OTPmeDaemon
from otpme.lib.classes.object_config import ObjectConfig
from otpme.lib.freeradius import reload as freeradius_reload

from otpme.lib.exceptions import *

LOCK_LOCK_TYPE = "cluster_lock"
JOURNAL_LOCK_TYPE = "cluster_journal"

node_checksums = []
last_node_check = time.time()
last_node_online_check = time.time()
processed_journal_entries = []
default_callback = config.get_callback()

REGISTER_BEFORE = ['otpme.lib.daemon.controld']
REGISTER_AFTER = []

CLUSTER_LOCK_NAME = "cluster_locks"
CLUSTER_LOCK_DIR = os.path.join(config.spool_dir, CLUSTER_LOCK_NAME)
CLUSTER_JOURNAL_NAME = "cluster_journal"
CLUSTER_JOURNAL_DIR = os.path.join(config.spool_dir, CLUSTER_JOURNAL_NAME)

def register():
    """ Register OTPme daemon. """
    config.register_otpme_daemon("clusterd")
    multiprocessing.register_shared_dict("node_votes")
    multiprocessing.register_shared_dict("sync_nodes")
    multiprocessing.register_shared_dict("master_node")
    multiprocessing.register_shared_dict("online_nodes")
    multiprocessing.register_shared_dict("member_nodes")
    multiprocessing.register_shared_dict("running_jobs")
    multiprocessing.register_shared_dict("cluster_writes")
    multiprocessing.register_shared_dict("cluster_quorum")
    multiprocessing.register_shared_list("init_sync_done")
    multiprocessing.register_shared_dict("node_connections")
    multiprocessing.register_shared_list("master_sync_done")
    multiprocessing.register_shared_list("init_sync_running")
    multiprocessing.register_shared_dict("radius_reload_queue")
    multiprocessing.register_shared_dict("nsscache_sync_queue")
    multiprocessing.register_shared_dict("peer_nodes_set_online")
    register_cluster_journal()

def register_cluster_journal():
    """ Directory to store cluster journal. """
    locking.register_lock_type(LOCK_LOCK_TYPE, module=__file__)
    locking.register_lock_type(JOURNAL_LOCK_TYPE, module=__file__)
    config.register_config_var("cluster_journal_dir", str, CLUSTER_JOURNAL_DIR)
    backend.register_data_dir(name=CLUSTER_JOURNAL_NAME,
                            path=CLUSTER_JOURNAL_DIR,
                            drop=True,
                            perms=0o770)
    config.register_config_var("cluster_lock_dir", str, CLUSTER_LOCK_DIR)
    backend.register_data_dir(name=CLUSTER_LOCK_NAME,
                            path=CLUSTER_LOCK_DIR,
                            drop=True,
                            perms=0o770)

def get_object_event(timestamp):
    object_event_name = "/cluster_journal_%s" % timestamp
    object_event = multiprocessing.Event(object_event_name)
    return object_event

def get_lock_event(timestamp):
    lock_event_name = "/%s" % timestamp
    lock_event = multiprocessing.Event(lock_event_name)
    return lock_event

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
    if not multiprocessing.cluster_event:
        return
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
    if not multiprocessing.cluster_event:
        return
    multiprocessing.cluster_event.set()

def cluster_sync_object(object_uuid, object_id, action, object_config=None,
    new_object_id=None, last_modified=None, checksum=None, wait_for_write=True):
    if config.one_node_setup:
        return
    handle_events = True
    if config.two_node_setup:
        if len(multiprocessing.online_nodes) == 0:
            if action != "delete":
                return
            handle_events = False
    if multiprocessing.cluster_event is None:
        return
    while True:
        try:
            cluster_journal_entry = ClusterJournalEntry(timestamp=time.time_ns(),
                                                    action=action,
                                                    object_uuid=object_uuid,
                                                    object_id=object_id,
                                                    checksum=checksum,
                                                    object_config=object_config,
                                                    new_object_id=new_object_id,
                                                    last_modified=last_modified)
        except AlreadyExists:
            continue
        else:
            break
    if not handle_events:
        return
    if not wait_for_write:
        try:
            cluster_journal_entry.commit()
        except Exception as e:
            msg = ("Failed to commit cluster journal entry: %s: %s"
                    % (object_id, e))
            config.logger.critical(msg)
            return
        multiprocessing.cluster_event.set()
        return
    if config.debug_level() > 2:
        msg = ("Waiting for cluster data write: %s %s %s"
                % (config.daemon_name, action, object_id))
        config.logger.debug(msg)
    object_event = get_object_event(cluster_journal_entry.timestamp)
    object_event.open()
    try:
        cluster_journal_entry.commit()
    except Exception as e:
        msg = ("Failed to commit cluster journal entry: %s: %s"
                % (object_id, e))
        config.logger.critical(msg)
        return
    multiprocessing.cluster_event.set()
    while True:
        try:
            object_event.wait(timeout=1)
        except TimeoutReached:
            continue
        object_event.clear()
        object_event.unlink()
        if config.debug_level() > 2:
            msg = ("Finished cluster data write: %s %s %s"
                    % (config.daemon_name, action, object_id))
            config.logger.debug(msg)
        break

def cluster_object_lock(action, lock_type,
    lock_id, write=False, timeout=None):
    if multiprocessing.cluster_lock_event is None:
        return
    if config.one_node_setup:
        return
    # No member nodes no cluster locks required.
    if len(multiprocessing.member_nodes) == 0:
        return
    if timeout is None:
        timeout = 3
    if timeout == 0:
        timeout = 3
    while True:
        try:
            cluster_lock_entry = ClusterLockEntry(timestamp=time.time_ns(),
                                                    action=action,
                                                    lock_type=lock_type,
                                                    lock_id=lock_id,
                                                    timeout=timeout,
                                                    write=write)
        except AlreadyExists:
            continue
        else:
            break
    if config.debug_level() > 2:
        msg = ("Waiting for cluster lock: %s %s %s"
                % (config.daemon_name, action, lock_id))
        config.logger.debug(msg)
        #print(msg)
    lock_event = get_lock_event(cluster_lock_entry.timestamp)
    lock_event.open()
    try:
        cluster_lock_entry.commit()
    except Exception as e:
        msg = ("Failed to commit cluster lock entry: %s: %s"
                % (lock_id, e))
        config.logger.critical(msg)
        return
    multiprocessing.cluster_lock_event.set()
    lock_event.wait()
    lock_event.clear()
    lock_event.unlink()
    if config.debug_level() > 2:
        msg = ("Finished cluster lock: %s %s %s"
                % (config.daemon_name, action, lock_id))
        config.logger.debug(msg)
        #print(msg)

    failed_nodes = cluster_lock_entry.get_failed_nodes()
    cluster_lock_entry.delete()
    if failed_nodes:
        raise LockWaitTimeout()

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
        node_vote = 0
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
    @entry_lock(write=True)
    def action(self, action):
        try:
            filetools.create_file(path=self.action_file,
                                    content=action)
        except Exception as e:
            msg = ("Failed to add action to cluster entry: %s: %s"
                    % (self.timestamp, e))
            self.logger.critical(msg)

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
                                content=str(time.time()))
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
        msg = ("Deleting cluster entry: %s" % self.timestamp)
        self.logger.debug(msg)
        try:
            shutil.rmtree(self.entry_dir)
        except FileNotFoundError:
            pass
        except Exception as e:
            msg = ("Failed to remove cluster entry: %s: %s"
                    % (self.entry_dir, e))
            self.logger.warning(msg)

class ClusterLockEntry(ClusterEntry):
    """ Cluster lock entry. """
    def __init__(self, timestamp, action=None, lock_type=None,
        lock_id=None, write=None, timeout=None):
        journal_dir = config.cluster_lock_dir
        super(ClusterLockEntry, self).__init__(journal_dir=journal_dir,
                                                _lock_type=LOCK_LOCK_TYPE,
                                                timestamp=timestamp,
                                                action=action)
        self.write_file = os.path.join(self.entry_dir, "write")
        self.lock_id_file = os.path.join(self.entry_dir, "lock_id")
        self.lock_type_file = os.path.join(self.entry_dir, "lock_type")
        self.timeout_file = os.path.join(self.entry_dir, "timeout")
        self.timeout_start_file = os.path.join(self.entry_dir, "timeout_start")
        if lock_id is not None:
            self.lock_id = lock_id
        if lock_type is not None:
            self.lock_type = lock_type
        if timeout is not None:
            self.timeout = timeout
        if write is not None:
            self.write = write

    def __str__(self):
        return self.lock_id

    def __repr__(self):
        # We need a string when object is used as dict key!
        return self.__str__()

    def __hash__(self):
        return hash(self.__str__())

    def __eq__(self, other):
        return self.lock_id == other.lock_id

    def __ne__(self, other):
        return self.lock_id != other.lock_id

    def __lt__(self, other):
        return self.__str__() < other.__str__()

    def __gt__(self, other):
        return self.__str__() > other.__str__()

    @property
    @entry_lock(write=False)
    def lock_id(self):
        try:
            lock_id = filetools.read_file(self.lock_id_file)
        except FileNotFoundError:
            lock_id = None
        except Exception as e:
            lock_id = None
            msg = ("Failed to read lock ID from cluster entry: %s: %s"
                    % (self.timeout, e))
            self.logger.critical(msg)
        return lock_id

    @lock_id.setter
    #@entry_lock(write=True)
    def lock_id(self, lock_id):
        try:
            filetools.create_file(path=self.lock_id_file,
                                    content=lock_id)
        except Exception as e:
            msg = ("Failed to add lock ID to cluster entry: %s: %s"
                    % (self.timestamp, e))
            self.logger.critical(msg)

    @property
    @entry_lock(write=False)
    def lock_type(self):
        try:
            lock_type = filetools.read_file(self.lock_type_file)
        except FileNotFoundError:
            lock_type = None
        except Exception as e:
            lock_type = None
            msg = ("Failed to read lock type from cluster entry: %s: %s"
                    % (self.timestamp, e))
            self.logger.critical(msg)
        return lock_type

    @lock_type.setter
    #@entry_lock(write=True)
    def lock_type(self, lock_type):
        try:
            filetools.create_file(path=self.lock_type_file,
                                    content=lock_type)
        except Exception as e:
            msg = ("Failed to add lock type to cluster entry: %s: %s"
                    % (self.timestamp, e))
            self.logger.critical(msg)

    @property
    @entry_lock(write=False)
    def timeout(self):
        try:
            timeout = filetools.read_file(self.timeout_file)
            timeout = float(timeout)
        except (FileNotFoundError, ValueError):
            timeout = None
        except Exception as e:
            timeout = None
            msg = ("Failed to read timeout from lock entry: %s: %s"
                    % (self.timestamp, e))
            self.logger.critical(msg)
        return timeout

    @timeout.setter
    #@entry_lock(write=True)
    def timeout(self, timeout):
        try:
            filetools.create_file(path=self.timeout_file,
                                    content=str(timeout))
        except Exception as e:
            msg = ("Failed to add timeout to cluster entry: %s: %s"
                    % (self.timestamp, e))
            self.logger.critical(msg)

    @property
    @entry_lock(write=False)
    def timeout_start(self):
        try:
            timeout_start = filetools.read_file(self.timeout_start_file)
            timeout_start = float(timeout_start)
        except (FileNotFoundError, ValueError):
            timeout_start = None
        except Exception as e:
            timeout_start = None
            msg = ("Failed to read timeout start from lock entry: %s: %s"
                    % (self.timestamp, e))
            self.logger.critical(msg)
        return timeout_start

    @timeout_start.setter
    @entry_lock(write=True)
    def timeout_start(self, timeout_start):
        try:
            filetools.create_file(path=self.timeout_start_file,
                                    content=str(timeout_start))
        except Exception as e:
            msg = ("Failed to add timeout start to cluster entry: %s: %s"
                    % (self.timestamp, e))
            self.logger.critical(msg)

    @property
    @entry_lock(write=False)
    def write(self):
        try:
            write = filetools.read_file(self.write_file)
            write = bool(write)
        except FileNotFoundError:
            write = False
        except Exception as e:
            write = False
            msg = ("Failed to read write from lock entry: %s: %s"
                    % (self.timestamp, e))
            self.logger.critical(msg)
        return write

    @write.setter
    #@entry_lock(write=True)
    def write(self, write):
        try:
            filetools.create_file(path=self.write_file,
                                    content=str(write))
        except Exception as e:
            msg = ("Failed to add write to cluster entry: %s: %s"
                    % (self.timestamp, e))
            self.logger.critical(msg)

class ClusterJournalEntry(ClusterEntry):
    """ Cluster journal entry. """
    def __init__(self, timestamp, object_uuid=None, action=None,
        object_id=None, checksum=None, object_config=None,
        new_object_id=None, last_modified=None):
        journal_dir = config.cluster_journal_dir
        super(ClusterJournalEntry, self).__init__(journal_dir=journal_dir,
                                                    _lock_type=JOURNAL_LOCK_TYPE,
                                                    timestamp=timestamp,
                                                    action=action)
        self.object_id_file = os.path.join(self.entry_dir, "object_id")
        self.object_uuid_file = os.path.join(self.entry_dir, "object_uuid")
        self.new_object_id_file = os.path.join(self.entry_dir, "new_object_id")
        self.object_config_file = os.path.join(self.entry_dir, "object_config")
        self.object_checksum_file = os.path.join(self.entry_dir, "object_checksum")
        self.last_modified_file = os.path.join(self.entry_dir, "last_modified")
        if action is not None:
            self.action = action
        if object_id is not None:
            self.object_id = object_id
        if object_uuid is not None:
            self.object_uuid = object_uuid
        if checksum is not None:
            self.object_checksum = checksum
        if new_object_id is not None:
            self.new_object_id = new_object_id
        if object_config is not None:
            self.object_config = object_config
        if last_modified is not None:
            self.last_modified = last_modified

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

    @property
    @entry_lock(write=False)
    def object_id(self):
        try:
            object_id = filetools.read_file(self.object_id_file)
        except FileNotFoundError:
            object_id = None
        except Exception as e:
            object_id = None
            msg = ("Failed to read object ID from lock entry: %s: %s"
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
            msg = ("Failed to read new object ID from lock entry: %s: %s"
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
            msg = ("Failed to read object UUID from lock entry: %s: %s"
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
            msg = ("Failed to read object checksum from lock entry: %s: %s"
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
    #@entry_lock(write=False)
    def last_modified(self):
        try:
            last_modified = filetools.read_file(self.last_modified_file)
        except FileNotFoundError:
            last_modified = None
        except Exception as e:
            last_modified = None
            msg = ("Failed to read last modified from lock entry: %s: %s"
                    % (self.timestamp, e))
            self.logger.critical(msg)
        return last_modified

    @last_modified.setter
    #@entry_lock(write=True)
    def last_modified(self, last_modified):
        try:
            filetools.create_file(path=self.last_modified_file,
                                    content=last_modified)
        except Exception as e:
            msg = ("Failed to add last modified to cluster entry: %s: %s"
                    % (self.timestamp, e))
            self.logger.critical(msg)

    @property
    @entry_lock(write=False)
    def object_config(self):
        if not os.path.exists(self.object_config_file):
            return
        object_id = oid.get(self.object_id, resolve=True)
        try:
            object_config = filetools.read_file(self.object_config_file)
        except FileNotFoundError:
            return None
        except Exception as e:
            msg = ("Failed to read object config from lock entry: %s: %s"
                    % (self.timestamp, e))
            self.logger.critical(msg)
            return None
        object_config = json.loads(object_config)
        object_config = ObjectConfig(object_id=object_id,
                                    object_config=object_config,
                                    encrypted=True)
        object_config = object_config.decrypt(config.master_key)
        object_config = object_config.copy()
        return object_config

    @object_config.setter
    #@entry_lock(write=True)
    def object_config(self, object_config):
        object_id = oid.get(self.object_id, resolve=True)
        object_config = ObjectConfig(object_id=object_id,
                                    object_config=object_config,
                                    encrypted=False)
        object_config = object_config.encrypt(config.master_key)
        object_config = object_config.copy()
        object_config = json.dumps(object_config)
        try:
            filetools.create_file(path=self.object_config_file,
                                    content=object_config)
        except Exception as e:
            msg = ("Failed to add object config to cluster entry: %s: %s"
                    % (self.timestamp, e))
            self.logger.critical(msg)

class ClusterDaemon(OTPmeDaemon):
    """ ClusterDaemon. """
    def __init__(self, *args, **kwargs):
        self.node_conn = None
        self.online_nodes = []
        self.node_offline = False
        self.member_candidate = False
        self.cluster_connections = {}
        self.lock_connections = {}
        self.init_sync_process = None
        self.cluster_comm_child = None
        self.interprocess_comm_child = None
        self.interprocess_lock_comm_child = None
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
        self.wait_for_cluster_writes()
        if config.start_freeradius:
            self.stop_freeradius()
        self.close_childs()
        return super(ClusterDaemon, self).signal_handler(_signal, frame)

    def wait_for_cluster_writes(self):
        time.sleep(0.5)
        while len(multiprocessing.cluster_writes) > 0:
            msg = "Waiting for pending cluster writes..."
            self.logger.info(msg)
            time.sleep(1)

    def start_childs(self):
        """ Start child processes childs. """
        msg = "Starting cluster communication..."
        self.logger.info(msg)
        # Remove left over lock entries.
        lock_journal_dirs = self.get_lock_journal()
        for lock_entry_dir in lock_journal_dirs:
            entry_timestamp = os.path.basename(lock_entry_dir)
            lock_journal_entry = ClusterLockEntry(timestamp=entry_timestamp)
            lock_journal_entry.delete()
        # Interprocess communication.
        self.interprocess_comm_child = multiprocessing.start_process(name=self.name,
                                        target=self.start_interprocess_comm)
        # Interprocess lock communication.
        self.interprocess_lock_comm_child = multiprocessing.start_process(name=self.name,
                                        target=self.start_interprocess_lock_comm)
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
        if self.interprocess_lock_comm_child:
            try:
                self.interprocess_lock_comm_child.terminate()
                self.interprocess_lock_comm_child.join()
            except Exception as e:
                msg = "Failed to stop cluster lock IPC child: %s" % e
                self.logger.warning(msg)
        if self.cluster_comm_child:
            try:
                self.cluster_comm_child.terminate()
                self.cluster_comm_child.join()
            except Exception as e:
                msg = "Failed to stop cluster communication child: %s" % e
                self.logger.warning(msg)

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

    def get_lock_journal(self):
        lock_journal_dirs = sorted(glob.glob(CLUSTER_LOCK_DIR + "/*"))
        return lock_journal_dirs

    def handle_journal_events(self):
        for cluster_entry_dir in self.get_cluster_journal():
            entry_timestamp = os.path.basename(cluster_entry_dir)
            cluster_journal_entry = ClusterJournalEntry(timestamp=entry_timestamp)
            try:
                if not cluster_journal_entry.committed:
                    continue
            except ObjectDeleted:
                continue
            object_event = get_object_event(entry_timestamp)
            object_event.set()
            object_event.close()
            object_event.unlink()

    def handle_lock_events(self):
        for lock_entry_dir in self.get_lock_journal():
            entry_timestamp = os.path.basename(lock_entry_dir)
            lock_journal_entry = ClusterLockEntry(timestamp=entry_timestamp)
            try:
                if not lock_journal_entry.committed:
                    continue
            except ObjectDeleted:
                continue
            lock_journal_entry.delete()
            lock_event = get_lock_event(entry_timestamp)
            lock_event.set()
            lock_event.close()
            lock_event.unlink()

    def node_leave(self, node_name):
        self.node_disconnect(node_name)
        try:
            multiprocessing.member_nodes.pop(node_name)
        except KeyError:
            pass
        try:
            multiprocessing.node_votes.pop(node_name)
        except KeyError:
            pass
        self.calc_quorum()

    def node_disconnect(self, node_name):
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
        try:
            multiprocessing.peer_nodes_set_online.pop(node_name)
        except KeyError:
            pass
        self.node_conn = None

    def get_conn_event_name(self, node_name):
        conn_even_name = "/cjournal-event-%s" % node_name
        return conn_even_name

    def get_lock_event_name(self, node_name):
        lock_event_name = "/clock-event-%s" % node_name
        return lock_event_name

    def do_init_sync(self, node_name):
        do_init_sync = False
        if node_name not in list(multiprocessing.init_sync_running):
            if node_name not in list(multiprocessing.init_sync_done):
                if self.host_name in multiprocessing.master_sync_done:
                    do_init_sync = True
        if not do_init_sync:
            return
        # We cannot clear cluster writes here because on node join this
        # will lead to loosing writes of the new node object.
        # Mark as initial sync running.
        multiprocessing.init_sync_running.append(node_name)
        # Start init sync process.
        self.init_sync_process = multiprocessing.start_process(name=self.name,
                                                target=self.start_initial_sync,
                                                target_args=(node_name,),
                                                join=True)

    def start_initial_sync(self, node_name):
        """ Start initial sync of sessions etc.. """
        # Set proctitle.
        new_proctitle = "%s (Initial sync %s)" % (self.full_name, node_name)
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
                config.raise_exception()
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
            self.wait_for_cluster_writes()
            # Cleanup IPC stuff.
            multiprocessing.cleanup()
            # Finally exit.
            os._exit(0)
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)
        while True:
            multiprocessing.cluster_event.wait()
            multiprocessing.cluster_event.clear()
            for node_name in multiprocessing.node_connections:
                conn_even_name = self.get_conn_event_name(node_name)
                conn_event = multiprocessing.Event(conn_even_name)
                conn_event.set()

    def start_interprocess_lock_comm(self):
        """ Start cluster interprocess communication. """
        # Set proctitle.
        new_proctitle = "%s (Cluster lock IPC)" % self.full_name
        setproctitle.setproctitle(new_proctitle)
        def signal_handler(_signal, frame):
            if _signal != 15:
                return
            self.wait_for_cluster_writes()
            # Cleanup IPC stuff.
            multiprocessing.cleanup()
            # Finally exit.
            os._exit(0)
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)
        while True:
            multiprocessing.cluster_lock_event.wait()
            multiprocessing.cluster_lock_event.clear()
            for node_name in multiprocessing.online_nodes:
                lock_event_name = self.get_lock_event_name(node_name)
                lock_event = multiprocessing.Event(lock_event_name)
                lock_event.set()

    def get_master_node(self, quiet=False):
        """ Get master node. """
        node_fails = {}

        while True:
            for node_name in multiprocessing.online_nodes:
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
                    self.node_disconnect(node_name)
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
                    self.node_disconnect(node_name)
                    msg = ("Failed to get cluster vote: %s: %s"
                            % (node_name, e))
                    self.logger.warning(msg)
                    x_node_vote = None
                if x_node_vote is None or x_node_vote == 0:
                    try:
                        multiprocessing.node_votes.pop(node_name)
                    except:
                        pass
                    continue
                if config.debug_level() > 2:
                    if not quiet:
                        msg = ("Got cluster vote from node: %s: %s"
                                % (node_name, x_node_vote))
                        self.logger.debug(msg)
                multiprocessing.node_votes[node_name] = x_node_vote

            conn_tries_done = True
            for x_node in multiprocessing.online_nodes:
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
            break

        node_vote = calc_node_vote()
        multiprocessing.node_votes[self.host_name] = node_vote

        node_scores = multiprocessing.node_votes.copy()
        x_sort = lambda x: node_scores[x]
        node_scores_sorted = sorted(node_scores, key=x_sort, reverse=True)
        new_master_node = node_scores_sorted[0]

        return new_master_node, node_scores

    def do_master_node_election(self):
        """ Do master node election. """
        # Get new master node.
        new_master_node, node_scores = self.get_master_node()

        try:
            old_master_node = multiprocessing.master_node['master']
        except KeyError:
            old_master_node = None
        if old_master_node != new_master_node:
            self.logger.info("Node votes: %s" % node_scores)

        required_votes = self.calc_quorum()[1]
        if len(node_scores) >= required_votes:
            return new_master_node
        msg = "Master node election failed: Not enough votes"
        for x in node_scores:
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

        try:
            master_node_candidate = self.get_master_node(quiet=True)[0]
        except MasterNodeElectionFailed as e:
            self.logger.critical(e)
            current_votes = 1
            quorum = False
            return current_votes, required_votes, quorum

        # Get current (active) node votes including own node.
        current_votes = 0
        node_vote = calc_node_vote()
        if node_vote > 0:
            current_votes = 1
        for node_name in multiprocessing.online_nodes:
            try:
                node = enabled_nodes[node_name]
            except KeyError:
                continue

            try:
                socket_uri = stuff.get_daemon_socket("clusterd", node_name)
            except Exception as e:
                msg = "Failed to get daemon socket: %s" % e
                self.logger.warning(msg)
                continue

            try:
                clusterd_conn = connections.get("clusterd",
                                                timeout=None,
                                                socket_uri=socket_uri)
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
                if not clusterd_conn.get_init_sync_status(self.host_name):
                    continue
            except Exception as e:
                self.node_disconnect(node_name)
                msg = ("Failed to get init sync status: %s: %s"
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
        elif len(enabled_nodes) == 2:
            config.two_node_setup = True
            config.one_node_setup = False
        else:
            config.two_node_setup = False
            config.one_node_setup = False

    def handle_node_connections(self):
        """ Handle node connections. """
        # Set node setup.
        self.set_node_setup()

        # Make sure left over events are handled.
        if config.one_node_setup:
            self.handle_journal_events()
            self.handle_lock_events()
        if config.two_node_setup:
            if len(multiprocessing.member_nodes) == 0:
                self.handle_journal_events()
                self.handle_lock_events()

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
            if self.cluster_connections:
                self.close_cluster_connections()
            if self.lock_connections:
                self.close_lock_connections()
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
            if node.name not in self.cluster_connections:
                # Start node connection process.
                cluster_proc = multiprocessing.start_process(name=self.name,
                                            target=self.start_cluster_connection,
                                            target_args=(node.name,))
                self.cluster_connections[node.name] = cluster_proc
            if node.name not in self.lock_connections:
                # Start node connection process.
                lock_prock = multiprocessing.start_process(name=self.name,
                                            target=self.start_lock_connection,
                                            target_args=(node.name,))
                self.lock_connections[node.name] = lock_prock
            multiprocessing.node_connections[node.name] = True
        # Remove connection to e.g. disabled nodes.
        for node_name in dict(self.cluster_connections):
            try:
                node = enabled_nodes[node_name]
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
                multiprocessing.node_connections.pop(node_name)
            except KeyError:
                pass
        for node_name in dict(self.lock_connections):
            try:
                node = enabled_nodes[node_name]
            except KeyError:
                node = None
            if node and node.enabled:
                continue
            lock_proc = self.lock_connections[node_name]
            lock_proc.terminate()
            lock_proc.join()
            self.lock_connections.pop(node_name)
        # Remove nodes not active anymore (e.g. deleted).
        for node_name in enabled_nodes:
            if node_name in self.cluster_connections:
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
                self.node_disconnect(master_node)
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
                socket_uri = stuff.get_daemon_socket("clusterd", node_name)
            except Exception as e:
                self.node_leave(node_name)
                if not quiet:
                    msg = ("Failed to get clusterd daemon socket: %s: %s"
                            % (node_name, e))
                    self.logger.warning(msg)
                return None
            try:
                self.node_conn = connections.get("clusterd",
                                                timeout=None,
                                                socket_uri=socket_uri,
                                                quiet_autoconnect=True)
            except Exception as e:
                self.node_leave(node_name)
                if not self.node_offline:
                    if not quiet:
                        msg = ("Failed to get cluster connection: %s: %s"
                                % (node_name, e))
                        self.logger.warning(msg)
                    self.node_offline = True
                return None
            else:
                multiprocessing.online_nodes[node_name] = True
                self.node_offline = False
                if not quiet:
                    msg = "Node is online: %s" % node_name
                    self.logger.info(msg)
                return self.node_conn

    def do_node_check(self, node_name):
        global last_node_check
        node_last_checked_time = time.time() - last_node_check
        if node_last_checked_time < 1:
            return False
        last_node_check = time.time()

        node_conn = self.get_node_connection(node_name)
        if not node_conn:
            return False

        try:
            self.do_init_sync(node_name)
        except Exception as e:
            self.node_disconnect(node_name)
            msg = "Failed to start initial sync: %s" % e
            self.logger.critical(msg)
            return False

        if self.host_name not in multiprocessing.master_sync_done:
            return False

        try:
            current_master_node = multiprocessing.master_node['master']
        except KeyError:
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
            self.node_disconnect(node_name)
            msg = "Failed to get node sync status: %s: %s" % (node_name, e)
            self.logger.critical(msg)
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

        msg = ("Starting initial sync with master node: %s"
                % master_node)
        self.logger.info(msg)
        max_tries = 3
        current_try = 0
        command_handler = CommandHandler()
        while True:
            skip_deletions = True
            if os.path.exists(config.node_joined_file):
                skip_deletions = False
            try:
                sync_status = command_handler.do_sync(sync_type="objects",
                                                    realm=config.realm,
                                                    site=config.site,
                                                    max_tries=10,
                                                    ignore_changed_objects=True,
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
                    return
                time.sleep(1)
                continue
            filetools.delete(config.node_joined_file)
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
            config.raise_exception()

    def _start_cluster_communication(self):
        """ Start cluster communication. """
        # Set proctitle.
        new_proctitle = "%s (Cluster communication)" % self.full_name
        setproctitle.setproctitle(new_proctitle)
        def signal_handler(_signal, frame):
            if _signal != 15:
                return
            self.wait_for_cluster_writes()
            # Close all cluster connections.
            self.close_cluster_connections()
            self.close_lock_connections()
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

            if self.host_name not in multiprocessing.master_sync_done:
                try:
                    current_master_node = self.get_master_node(quiet=True)[0]
                except MasterNodeElectionFailed as e:
                    self.logger.critical(e)
                    time.sleep(quorum_check_interval)
                    continue
                if current_master_node == self.host_name:
                    multiprocessing.master_sync_done.append(self.host_name)
                else:
                    self.do_master_node_sync(current_master_node)

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

            nodes_ready = True
            for node_name in multiprocessing.online_nodes:
                if node_name in multiprocessing.init_sync_done:
                    continue
                nodes_ready = False
                break

            if not nodes_ready:
                time.sleep(quorum_check_interval)
                continue

            # For two node clusters wait 30 seconds for second node to appear.
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

            try:
                self.switch_master_node(current_master_node, new_master_node)
            except Exception as e:
                msg = "Failed to switch master node: %s" % e
                self.logger.critical(msg)

            config.master_failover = False
            time.sleep(quorum_check_interval)

    def handle_two_node_setup(self):
        # Two node setups require some special handling if second node is down.
        if not config.two_node_setup:
            return
        if len(multiprocessing.member_nodes) > 0:
            return
        try:
            self.handle_journal_events()
        except Exception as e:
            msg = "Failed to handle events: %s" % e
            self.logger.critical(msg)
            #print(msg)

    def set_node_online(self, node_name):
        """ Set node online. """
        global last_node_online_check
        node_last_checked_time = time.time() - last_node_online_check
        if node_last_checked_time < 3:
            return True
        last_node_online_check = time.time()
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

    def start_lock_connection(self, *args, **kwargs):
        """ Start cluster lock connection. """
        try:
            self._start_lock_connection(*args, **kwargs)
        except Exception as e:
            msg = "Error in cluster connection method: %s" % e
            self.logger.critical(msg)
            config.raise_exception()

    def _start_lock_connection(self, node_name):
        """ Start cluster lock communication with node. """
        # Set proctitle.
        new_proctitle = ("%s Cluster lock (%s)"
                        % (self.full_name, node_name))
        setproctitle.setproctitle(new_proctitle)

        lock_event_name = self.get_lock_event_name(node_name)
        lock_event = multiprocessing.Event(lock_event_name)

        def signal_handler(_signal, frame):
            if _signal != 15:
                return
            self.wait_for_cluster_writes()
            # Cleanup IPC stuff.
            if self.node_conn:
                self.node_conn.close()
            lock_event.unlink()
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
            # Wait for cluster lock event.
            event_timeout = 3
            if start_over:
                event_timeout = 0.05
            try:
                lock_event.wait(timeout=event_timeout)
            except TimeoutReached:
                pass
            finally:
                lock_event.clear()

            if config.two_node_setup:
                if len(multiprocessing.member_nodes) == 0:
                    lock_journal_dirs = self.get_lock_journal()
                    for lock_entry_dir in lock_journal_dirs:
                        entry_timestamp = os.path.basename(lock_entry_dir)
                        lock_journal_entry = ClusterLockEntry(timestamp=entry_timestamp)
                        try:
                            if not lock_journal_entry.committed:
                                continue
                            self.check_lock_nodes(lock_journal_entry)
                        except ObjectDeleted:
                            continue
                    start_over = True
                    continue

            if not self.node_conn:
                node_conn = self.get_node_connection(node_name, quiet=True)
                if not node_conn:
                    start_over = True
                    continue

            try:
                start_over = self.handle_lock_journal(node_name)
            except Exception as e:
                start_over = True
                msg = "Failed to handle lock journal: %s" % e
                self.logger.critical(msg)
                #print(msg)
                config.raise_exception()

    def handle_lock_journal(self, node_name):
        """ Handle lock journal. """
        lock_journal_dirs = self.get_lock_journal()
        for lock_entry_dir in lock_journal_dirs:
            entry_timestamp = os.path.basename(lock_entry_dir)
            lock_journal_entry = ClusterLockEntry(timestamp=entry_timestamp)
            try:
                if not lock_journal_entry.committed:
                    continue
                if node_name not in multiprocessing.online_nodes:
                    self.check_lock_nodes(lock_journal_entry)
                    return True
                write = lock_journal_entry.write
                action = lock_journal_entry.action
                lock_id = lock_journal_entry.lock_id
                lock_type = lock_journal_entry.lock_type
                lock_entry_nodes = lock_journal_entry.get_nodes()
                lock_entry_failed_nodes = lock_journal_entry.get_failed_nodes()
                if node_name in lock_entry_nodes:
                    if lock_entry_failed_nodes:
                        if node_name not in lock_entry_failed_nodes:
                            msg = "Releasing failed lock: %s: %s" % (node_name, lock_id)
                            self.logger.debug(msg)
                            try:
                                self.node_conn.release_lock(lock_id, write)
                            except (ConnectionTimeout, ConnectionError, ConnectionQuit) as e:
                                msg = "Failed to release lock: %s" % e
                                self.logger.critical(msg)
                                self.node_disconnect(node_name)
                                return True
                            except UnknownLock:
                                pass
                            except Exception as e:
                                msg = "Error releasing lock: %s" % e
                                self.logger.critical(msg)
                                self.node_disconnect(node_name)
                                return True
                            lock_journal_entry.add_failed_node(node_name)
                        lock_journal_entry.add_node(node_name)
                        self.check_lock_nodes(lock_journal_entry)
                    continue

                if self.node_conn is None:
                    return True

                if action == "lock":
                    timeout = lock_journal_entry.timeout
                    if timeout == 0:
                        timeout = 1
                    if lock_journal_entry.timeout_start is None:
                        lock_journal_entry.timeout_start = time.time()
                    if time.time() < (lock_journal_entry.timeout_start + timeout):
                        msg = "Acquiring lock: %s: %s" % (node_name, lock_id)
                        self.logger.debug(msg)
                        try:
                            self.node_conn.acquire_lock(lock_type, lock_id, write)
                        except (ConnectionTimeout, ConnectionError, ConnectionQuit) as e:
                            msg = "Failed to acquire lock: %s" % e
                            self.logger.warning(msg)
                            self.node_disconnect(node_name)
                            return True
                        except LockWaitAbort:
                            continue
                        except Exception as e:
                            msg = "Error acquiring lock: %s" % e
                            self.logger.critical(msg)
                            self.node_disconnect(node_name)
                            return True
                    else:
                        lock_journal_entry.add_failed_node(node_name)

                if action == "release":
                    msg = "Releasing lock: %s: %s" % (node_name, lock_id)
                    self.logger.debug(msg)
                    try:
                        self.node_conn.release_lock(lock_id, write)
                    except (ConnectionTimeout, ConnectionError, ConnectionQuit) as e:
                        msg = "Failed to release lock: %s" % e
                        self.logger.critical(msg)
                        self.node_disconnect(node_name)
                        return True
                    except UnknownLock:
                        pass
                    except Exception as e:
                        msg = "Error releasing lock: %s" % e
                        self.logger.critical(msg)
                        self.node_disconnect(node_name)
                        return True
                # Add node to journal entry.
                lock_journal_entry.add_node(node_name)
                # Check if lock was sent to all online nodes.
                self.check_lock_nodes(lock_journal_entry)
            except ObjectDeleted:
                pass

        journal_entries = self.get_lock_journal()
        if journal_entries:
            return True

        return False

    def check_lock_nodes(self, lock_journal_entry):
        """ Make sure locks are sent to all online nodes. """
        online_nodes_in_sync = True
        for node_name in multiprocessing.online_nodes:
            if node_name in lock_journal_entry.get_nodes():
                continue
            online_nodes_in_sync = False
            break
        failed_nodes = lock_journal_entry.get_failed_nodes()
        if failed_nodes:
            for node_name in multiprocessing.online_nodes:
                if node_name in failed_nodes:
                    continue
                online_nodes_in_sync = False
                break
        if not online_nodes_in_sync:
            return False
        lock_event = get_lock_event(lock_journal_entry.timestamp)
        lock_event.set()
        lock_event.unlink()
        return True

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
            self.wait_for_cluster_writes()
            # Cleanup IPC stuff.
            if self.node_conn:
                self.node_conn.close()
            conn_event.unlink()
            multiprocessing.cleanup()
            if self.init_sync_process:
                self.init_sync_process.terminate()
                self.init_sync_process.join()
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
            event_timeout = 3
            if start_over:
                event_timeout = 0.05

            try:
                conn_event.wait(timeout=event_timeout)
            except TimeoutReached:
                pass
            finally:
                conn_event.clear()

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
                            if not cluster_journal_entry.committed:
                                continue
                            if not self.check_member_nodes(cluster_journal_entry):
                                continue
                            self.check_online_nodes(cluster_journal_entry)
                        except ObjectDeleted:
                            pass

            # Mark node as online on peer node.
            start_over= False
            if not self.set_node_online(node_name):
                start_over = True
                continue

            do_node_check = False
            if node_name not in multiprocessing.member_nodes:
                do_node_check = True
            if node_name not in multiprocessing.init_sync_done:
                do_node_check = True

            if do_node_check:
                if not self.do_node_check(node_name):
                    start_over = True
                    continue

            if node_name not in multiprocessing.online_nodes:
                start_over = True
                continue

            try:
                start_over = self.handle_cluster_journal(node_name)
            except Exception as e:
                start_over = True
                msg = "Failed to handle cluster journal: %s" % e
                self.logger.critical(msg)
                #print(msg)
                config.raise_exception()

            # Add node to cluster member nodes.
            if self.member_candidate:
                self.member_candidate = False
                multiprocessing.member_nodes[node_name] = True
                msg = "Node joined the cluster: %s" % node_name
                self.logger.info(msg)

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
        # If online nodes changed we have to re-check all cluster entries.
        if self.online_nodes != sorted(multiprocessing.online_nodes.keys()):
            processed_journal_entries.clear()
            self.online_nodes = sorted(multiprocessing.online_nodes.keys())
        if len(node_checksums) > 102400:
            node_checksums = node_checksums[51200:]
        if len(processed_journal_entries) > 102400:
            processed_journal_entries = processed_journal_entries[51200:]
        uuids_to_process = []
        entries_to_process = []
        cluster_journal_dirs = self.get_cluster_journal()
        for journal_entry_dir in cluster_journal_dirs:
            if not config.cluster_status:
                return True
            if self.node_conn is None:
                return True
            entry_timestamp = os.path.basename(journal_entry_dir)
            if entry_timestamp in processed_journal_entries:
                continue
            cluster_journal_entry = ClusterJournalEntry(timestamp=entry_timestamp)
            try:
                if not cluster_journal_entry.committed:
                    continue
                if not self.member_candidate:
                    if node_name not in multiprocessing.member_nodes:
                        # Check if object was written to member nodes
                        if self.check_member_nodes(cluster_journal_entry):
                            # Check if object was written to all online nodes.
                            self.check_online_nodes(cluster_journal_entry)
                        return False
                if node_name in cluster_journal_entry.get_nodes():
                    processed_journal_entries.append(cluster_journal_entry.timestamp)
                    # Check if object was written to member nodes
                    if self.check_member_nodes(cluster_journal_entry):
                        # Check if object was written to all online nodes.
                        self.check_online_nodes(cluster_journal_entry)
                    continue
                entries_to_process.append(cluster_journal_entry.timestamp)
                if cluster_journal_entry.action != "delete":
                    uuids_to_process.append(cluster_journal_entry.object_uuid)
            except ObjectDeleted:
                pass

        written_entries = []
        unsync_status_set = False
        for entry_timestamp in entries_to_process:
            if not config.cluster_status:
                return True
            self.handle_two_node_setup()
            cluster_journal_entry = ClusterJournalEntry(timestamp=entry_timestamp)
            try:
                object_id = cluster_journal_entry.object_id
                object_id = oid.get(object_id)
                object_uuid = cluster_journal_entry.object_uuid
                object_config = cluster_journal_entry.object_config
                object_checksum = cluster_journal_entry.object_checksum
                last_modified = cluster_journal_entry.last_modified
                # We need to read action last because it will throw
                # ObjectDeleted exception if the cluster entry was deleted.
                action = cluster_journal_entry.action

                # Skip duplicated entries we've already written.
                # We only need to write the first and the last occurence.
                if action == "delete":
                    try:
                        uuids_to_process.remove(object_uuid)
                    except ValueError:
                        pass
                else:
                    # Skip duplicate object writes.
                    if object_uuid in written_entries:
                        try:
                            uuids_to_process.remove(object_uuid)
                        except ValueError:
                            pass
                        if object_uuid in uuids_to_process:
                            msg = ("Skipping duplicated cluster journal entry: %s"
                                    % (object_id))
                            self.logger.debug(msg)
                            # Check if object was written to member nodes
                            if self.check_member_nodes(cluster_journal_entry):
                                # Check if object was written to all online nodes.
                                self.check_online_nodes(cluster_journal_entry)
                            cluster_journal_entry.delete()
                            continue

                    if object_checksum in node_checksums:
                        cluster_journal_entry.add_node(node_name)
                        processed_journal_entries.append(cluster_journal_entry.timestamp)
                        # Check if object was written to member nodes
                        if self.check_member_nodes(cluster_journal_entry):
                            # Check if object was written to all online nodes.
                            self.check_online_nodes(cluster_journal_entry)
                        continue

                # Mark node as out of sync (tree objects).
                if object_id.object_type in config.tree_object_types:
                    if not unsync_status_set:
                        unsync_status_set = True
                        self.unset_node_sync(node_name)
                # Write object to peer.
                if action == "write":
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
                        self.node_disconnect(node_name)
                        msg = ("Failed to send object: %s: %s: %s"
                                % (node_name, object_id, e))
                        self.logger.warning(msg)
                        return True
                    except Exception as e:
                        self.node_disconnect(node_name)
                        msg = ("Error sending object: %s: %s: %s"
                                % (node_name, object_id, e))
                        self.logger.warning(msg)
                        return True
                    if write_status != "done":
                        continue
                    written_entries.append(object_uuid)
                    try:
                        uuids_to_process.remove(object_uuid)
                    except ValueError:
                        pass
                    msg = ("Written object to node: %s: %s (%s)"
                            % (node_name, object_id, object_checksum))
                    self.logger.debug(msg)
                    node_checksums.append(object_checksum)
                    cluster_journal_entry.add_node(node_name)
                    processed_journal_entries.append(cluster_journal_entry.timestamp)
                # Rename object on peer.
                if action == "rename":
                    new_object_id = cluster_journal_entry.new_object_id
                    new_object_id = oid.get(new_object_id)
                    try:
                        rename_status = self.node_conn.rename(object_uuid=object_uuid,
                                                        object_id=object_id.full_oid,
                                                        new_object_id=new_object_id.full_oid)
                    except (ConnectionTimeout, ConnectionError, ConnectionQuit) as e:
                        self.node_disconnect(node_name)
                        msg = ("Failed to rename object: %s: %s: %s"
                                % (node_name, object_id, e))
                        self.logger.warning(msg)
                        return True
                    except Exception as e:
                        self.node_disconnect(node_name)
                        msg = ("Failed to rename object: %s: %s: %s"
                                % (node_name, object_id, e))
                        self.logger.warning(msg)
                        return True
                    if rename_status != "done":
                        continue
                    written_entries.append(object_uuid)
                    try:
                        uuids_to_process.remove(object_uuid)
                    except ValueError:
                        pass
                    msg = ("Renamed object on node: %s: %s: %s"
                            % (node_name, object_id, new_object_id))
                    self.logger.debug(msg)
                    node_checksums.append(object_checksum)
                    cluster_journal_entry.add_node(node_name)
                    processed_journal_entries.append(cluster_journal_entry.timestamp)
                # Delete object on peer.
                if action == "delete":
                    try:
                        del_status = self.node_conn.delete(object_uuid,
                                                        object_id.full_oid)
                    except (ConnectionTimeout, ConnectionError, ConnectionQuit) as e:
                        self.node_disconnect(node_name)
                        msg = "Failed to delete object: %s: %s" % (object_id, e)
                        self.logger.warning(msg)
                        return True
                    except Exception as e:
                        self.node_disconnect(node_name)
                        msg = "Failed to delete object: %s: %s" % (object_id, e)
                        self.logger.warning(msg)
                        return True
                    if del_status != "done":
                        continue
                    msg = ("Deleted object on node: %s: %s"
                            % (node_name, object_id))
                    self.logger.debug(msg)
                    node_checksums.append(object_checksum)
                    cluster_journal_entry.add_node(node_name)
                    processed_journal_entries.append(cluster_journal_entry.timestamp)

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
                self.set_node_sync(node_name, sync_time-300)

        journal_entries = self.get_cluster_journal()
        if journal_entries:
            return True

        return False

    def set_node_sync(self, node_name, sync_time):
        try:
            self.node_conn.set_node_sync(sync_time)
        except (ConnectionTimeout, ConnectionError, ConnectionQuit) as e:
            self.node_disconnect(node_name)
            msg = ("Failed to set cluster sync state: %s: %s"
                    % (node_name, e))
            self.logger.warning(msg)
        except Exception as e:
            self.node_disconnect(node_name)
            msg = ("Error setting cluster sync state: %s: %s"
                    % (node_name, e))
            self.logger.warning(msg)

    def unset_node_sync(self, node_name):
        try:
            self.node_conn.unset_node_sync()
        except (ConnectionTimeout, ConnectionError, ConnectionQuit) as e:
            self.node_disconnect(node_name)
            msg = ("Failed to unset cluster sync state: %s: %s"
                    % (node_name, e))
            self.logger.warning(msg)
        except Exception as e:
            self.node_disconnect(node_name)
            msg = ("Error unsetting cluster sync state: %s: %s"
                    % (node_name, e))
            self.logger.warning(msg)

    def check_online_nodes(self, cluster_journal_entry):
        if not config.cluster_status:
            return
        online_nodes_in_sync = True
        for node_name in multiprocessing.online_nodes:
            if node_name in cluster_journal_entry.get_nodes():
                continue
            online_nodes_in_sync = False
        if not online_nodes_in_sync:
            return
        # Delete journal entries must be synced to all nodes
        # even offline ones.
        all_nodes_in_sync = True
        if cluster_journal_entry.action == "delete":
            all_nodes = backend.search(object_type="node",
                                attribute="name",
                                value="*",
                                realm=config.realm,
                                site=config.site,
                                return_type="name")
            for node_name in all_nodes:
                if node_name == self.host_name:
                    continue
                if node_name in cluster_journal_entry.get_nodes():
                    continue
                all_nodes_in_sync = False
        if not all_nodes_in_sync:
            return
        object_event = get_object_event(cluster_journal_entry.timestamp)
        object_event.set()
        object_event.unlink()
        cluster_journal_entry.delete()

    def check_member_nodes(self, cluster_journal_entry):
        if not config.cluster_status:
            return
        member_nodes_in_sync = True
        for node_name in multiprocessing.member_nodes:
            if node_name in cluster_journal_entry.get_nodes():
                continue
            member_nodes_in_sync = False
        if not member_nodes_in_sync:
            return False
        object_event = get_object_event(cluster_journal_entry.timestamp)
        object_event.set()
        object_event.unlink()
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
        for node_name in list(self.cluster_connections):
            cluster_proc = self.cluster_connections[node_name]
            cluster_proc.terminate()
            cluster_proc.join()
            self.cluster_connections.pop(node_name)
            self.node_leave(node_name)

    def close_lock_connections(self):
        """ Close all cluster lock connections. """
        for node_name in dict(self.lock_connections):
            lock_proc = self.lock_connections[node_name]
            lock_proc.terminate()
            lock_proc.join()
            self.lock_connections.pop(node_name)

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
