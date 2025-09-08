# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import re
import time
import glob
import shutil
import signal
import setproctitle
from functools import wraps

try:
    import simdjson as json
except:
    try:
        import ujson as json
    except:
        import json

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
from otpme.lib import filetools
from otpme.lib import connections
from otpme.lib import sign_key_cache
from otpme.lib import multiprocessing
from otpme.lib.pidfile import is_running
from otpme.lib.protocols import status_codes
from otpme.lib.daemon.otpme_daemon import OTPmeDaemon
#from otpme.lib.classes.object_config import ObjectConfig
from otpme.lib.freeradius.utils import reload as freeradius_reload

from otpme.lib.exceptions import *

JOURNAL_LOCK_TYPE = "cluster_journal"

default_callback = config.get_callback()

REGISTER_BEFORE = ['otpme.lib.daemon.controld']
REGISTER_AFTER = []

CLUSTER_IN_JOURNAL_NAME = "cluster_in_journal"
CLUSTER_IN_JOURNAL_DIR = os.path.join(config.spool_dir, CLUSTER_IN_JOURNAL_NAME)
CLUSTER_OUT_JOURNAL_NAME = "cluster_out_journal"
CLUSTER_OUT_JOURNAL_DIR = os.path.join(config.spool_dir, CLUSTER_OUT_JOURNAL_NAME)

TRASH_JOURNAL_DIR = os.path.join(CLUSTER_OUT_JOURNAL_DIR, "trash")
OBJECTS_JOURNAL_DIR = os.path.join(CLUSTER_OUT_JOURNAL_DIR, "objects")
LAST_USED_JOURNAL_DIR = os.path.join(CLUSTER_OUT_JOURNAL_DIR, "last_used")

def register():
    """ Register OTPme daemon. """
    config.register_otpme_daemon("clusterd")
    multiprocessing.register_shared_dict("node_vote")
    multiprocessing.register_shared_dict("ready_nodes")
    multiprocessing.register_shared_dict("master_node")
    multiprocessing.register_shared_dict("online_nodes")
    multiprocessing.register_shared_dict("member_nodes")
    multiprocessing.register_shared_list("pause_writes")
    multiprocessing.register_shared_dict("running_jobs")
    multiprocessing.register_shared_dict("cluster_quorum")
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
    backend.register_data_dir(name=CLUSTER_IN_JOURNAL_NAME,
                            path=CLUSTER_IN_JOURNAL_DIR,
                            drop=True,
                            perms=0o770)
    backend.register_data_dir(name=CLUSTER_OUT_JOURNAL_NAME,
                            path=CLUSTER_OUT_JOURNAL_DIR,
                            drop=True,
                            perms=0o770)

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

def cluster_sync_object(action, object_id=None, object_uuid=None,
    object_type=None, object_data=None, old_object_id=None,
    new_object_id=None, index_journal=None, acl_journal=None,
    trash_id=None, deleted_by=None, wait_for_write=True):
    if config.host_type != "node":
        return (None, None)
    if not multiprocessing.cluster_out_event:
        return (None, None)
    if config.one_node_setup:
        return (None, None)
    if config.two_node_setup:
        if len(multiprocessing.online_nodes) == 0:
            if action != "delete":
                if action != "trash_delete":
                    return (None, None)
            wait_for_write = False
    while len(multiprocessing.pause_writes) > 0:
        time.sleep(0.1)

    timestamp = time.time_ns()
    if action == "write":
        journal_id = object_uuid
        journal_dir = OBJECTS_JOURNAL_DIR
    if action == "delete":
        journal_id = object_uuid
        journal_dir = OBJECTS_JOURNAL_DIR
    if action == "rename":
        journal_id = object_uuid
        journal_dir = OBJECTS_JOURNAL_DIR
    if action == "last_used_write":
        journal_id = object_uuid
        journal_dir = LAST_USED_JOURNAL_DIR
    if action == "trash_write":
        journal_id = timestamp
        journal_dir = TRASH_JOURNAL_DIR
    if action == "trash_delete":
        journal_id = timestamp
        journal_dir = TRASH_JOURNAL_DIR
    if action == "trash_empty":
        journal_id = timestamp
        journal_dir = TRASH_JOURNAL_DIR

    while True:
        try:
            cluster_journal_entry = ClusterJournalEntry(journal_id=journal_id,
                                                        journal_dir=journal_dir,
                                                        timestamp=timestamp,
                                                        object_uuid=object_uuid)
            cluster_journal_entry.lock(write=True)
        except ObjectDeleted:
            continue
        break

    if action == "delete":
        if cluster_journal_entry.committed:
            cluster_journal_entry.release()
            while True:
                try:
                    cluster_journal_entry.delete()
                    cluster_journal_entry = ClusterJournalEntry(journal_id=journal_id,
                                                                journal_dir=journal_dir,
                                                                timestamp=timestamp,
                                                                object_uuid=object_uuid)
                    cluster_journal_entry.lock(write=True)
                except ObjectDeleted:
                    continue
                break

    try:
        if object_id:
            cluster_journal_entry.object_id = object_id
        if object_type:
            cluster_journal_entry.object_type = object_type
        if trash_id:
            cluster_journal_entry.trash_id = trash_id
        if deleted_by:
            cluster_journal_entry.deleted_by = deleted_by
        if object_data:
            cluster_journal_entry.object_data = object_data
        if acl_journal:
            cluster_journal_entry.add_acl_journal(acl_journal)
        if index_journal:
            cluster_journal_entry.add_index_journal(index_journal)
        if action == "rename":
            cluster_journal_entry.add_action(action=action,
                                        old_object_id=old_object_id.full_oid,
                                        new_object_id=new_object_id.full_oid)
        else:
            cluster_journal_entry.add_action(action=action)
        if not wait_for_write:
            try:
                cluster_journal_entry.commit()
            except Exception as e:
                msg = ("Failed to commit cluster journal entry: %s: %s"
                        % (object_id, e))
                config.logger.critical(msg)
                return (None, None)
            multiprocessing.cluster_out_event.set()
            return (None, None)
        object_event = cluster_journal_entry.add_object_event(timestamp)
        object_event.open()
        try:
            cluster_journal_entry.commit()
        except Exception as e:
            msg = ("Failed to commit cluster journal entry: %s: %s"
                    % (object_id, e))
            config.logger.critical(msg)
            return (None, None)
    finally:
        cluster_journal_entry.release()

    multiprocessing.cluster_out_event.set()
    return (object_event, timestamp)

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
    def __init__(self, journal_dir, journal_id, _lock_type=None, **kwargs):
        self._lock = None
        self._lock_type = _lock_type
        self.journal_id = str(journal_id)
        self.logger = config.logger
        self.entry_dir = os.path.join(journal_dir, self.journal_id)
        self.nodes_dir = os.path.join(self.entry_dir, "nodes")
        self.commit_file = os.path.join(self.entry_dir, "ready")
        self.failed_nodes_dir = os.path.join(self.entry_dir, "failed_nodes")

        self.actions_file = os.path.join(self.entry_dir, "action")
        self.timestamp_file = os.path.join(self.entry_dir, "timestamp")
        self.object_id_file = os.path.join(self.entry_dir, "object_id")
        self.object_type_file = os.path.join(self.entry_dir, "object_type")
        self.object_uuid_file = os.path.join(self.entry_dir, "object_uuid")
        self.index_journal_file = os.path.join(self.entry_dir, "index_journal")
        self.acl_journal_file = os.path.join(self.entry_dir, "acl_journal")
        self.trash_id_file = os.path.join(self.entry_dir, "trash_id")
        self.deleted_by_file = os.path.join(self.entry_dir, "deleted_by")
        self.object_data_file = os.path.join(self.entry_dir, "object_data")

    def lock(self, write=False):
        if self._lock:
            return
        self._lock = locking.acquire_lock(lock_type=self._lock_type,
                                        lock_id=self.journal_id,
                                        write=write)
        if not os.path.exists(self.entry_dir):
            msg = "Entry deleted while waiting for lock: %s" % self.journal_id
            self.release()
            raise ObjectDeleted(msg)
        return self._lock

    def release(self):
        if not self._lock:
            return
        try:
            self._lock.release_lock()
        except Exception as e:
            msg = ("Failed to release cluster entry lock: %s: %s"
                    % (self.journal_id, e))
            self.logger.warning(msg)
        self._lock = None

    @property
    #@entry_lock(write=True)
    def pid(self):
        try:
            pid = filetools.read_file(self.commit_file)
        except FileNotFoundError:
            pid = None
        if pid:
            pid = int(pid)
        return pid

    @property
    #@entry_lock(write=False)
    def committed(self):
        if os.path.exists(path=self.commit_file):
            return True
        return False

    #@entry_lock(write=True)
    def commit(self):
        try:
            filetools.create_file(path=self.commit_file,
                                content=str(os.getpid()))
        except Exception as e:
            msg = ("Failed to commit cluster entry: %s: %s"
                    % (self.journal_id, e))
            self.logger.critical(msg)
        # Remove committed nodes.
        self.remove_nodes()

    #@entry_lock(write=True)
    def add_node(self, node_name):
        node_file = os.path.join(self.nodes_dir, node_name)
        try:
            filetools.create_file(path=node_file, content=str(time.time()))
        except FileNotFoundError:
            raise ObjectDeleted()
        except Exception as e:
            msg = ("Failed to add node to cluster entry: %s: %s"
                    % (node_name, e))
            self.logger.critical(msg)

    #@entry_lock(write=False)
    def remove_nodes(self):
        nodes_files = sorted(glob.glob(self.nodes_dir + "/*"))
        for node_file in nodes_files:
            node_name = os.path.basename(node_file)
            try:
                os.remove(node_file)
            except FileNotFoundError:
                pass
            except Exception as e:
                msg = ("Failed to remove node from cluster entry: %s: %s"
                        % (node_name, e))
                self.logger.critical(msg)

    #@entry_lock(write=False)
    def get_nodes(self):
        nodes = []
        nodes_files = sorted(glob.glob(self.nodes_dir + "/*"))
        for node_file in nodes_files:
            node_name = os.path.basename(node_file)
            nodes.append(node_name)
        file_glob = "%s*" % self.actions_file
        actions_files = sorted(glob.glob(file_glob))
        actions_file_re = re.compile('^%s.[0-9]*$' % self.actions_file)
        done_nodes = list(nodes)
        processed_nodes = []
        for x_file in actions_files:
            if len(processed_nodes) == len(nodes):
                break
            if not actions_file_re.match(x_file):
                continue
            for node in nodes:
                x_node_file = "%s.%s" % (x_file, node)
                if os.path.exists(x_node_file):
                    continue
                try:
                    done_nodes.remove(node)
                except ValueError:
                    pass
                if node in processed_nodes:
                    continue
                processed_nodes.append(node)
        file_glob = "%s*" % self.index_journal_file
        index_journal_files = sorted(glob.glob(file_glob))
        journal_file_re = re.compile('^%s.[0-9]*$' % self.index_journal_file)
        done_nodes = list(nodes)
        processed_nodes = []
        for x_file in index_journal_files:
            if len(processed_nodes) == len(nodes):
                break
            if not journal_file_re.match(x_file):
                continue
            for node in nodes:
                x_node_file = "%s.%s" % (x_file, node)
                if os.path.exists(x_node_file):
                    continue
                try:
                    done_nodes.remove(node)
                except ValueError:
                    pass
                if node in processed_nodes:
                    continue
                processed_nodes.append(node)
        file_glob = "%s*" % self.acl_journal_file
        acl_journal_files = sorted(glob.glob(file_glob))
        journal_file_re = re.compile('^%s.[0-9]*$' % self.acl_journal_file)
        processed_nodes = []
        for x_file in acl_journal_files:
            if len(processed_nodes) == len(nodes):
                break
            if not journal_file_re.match(x_file):
                continue
            for node in nodes:
                x_node_file = "%s.%s" % (x_file, node)
                if os.path.exists(x_node_file):
                    continue
                try:
                    done_nodes.remove(node)
                except ValueError:
                    pass
                if node in processed_nodes:
                    continue
                processed_nodes.append(node)
        return done_nodes

    #@entry_lock(write=True)
    def add_failed_node(self, node_name):
        node_file = os.path.join(self.failed_nodes_dir, node_name)
        try:
            filetools.create_file(path=node_file, content=str(time.time()))
        except Exception as e:
            msg = ("Failed to add failed node to cluster entry: %s: %s"
                    % (node_name, e))
            self.logger.critical(msg)

    #@entry_lock(write=False)
    def get_failed_nodes(self):
        nodes = []
        for node_file in sorted(glob.glob(self.failed_nodes_dir + "/*")):
            node_name = os.path.basename(node_file)
            nodes.append(node_name)
        return nodes

    @entry_lock(write=True)
    def delete(self):
        object_id = self.object_id
        random_part = stuff.gen_secret(len=8)
        entry_del_dir = "%s-%s.deleting" % (self.entry_dir, random_part)
        try:
            os.rename(self.entry_dir, entry_del_dir)
        except FileNotFoundError:
            return
        except Exception as e:
            msg = "Failed to rename cluster entry dir: %s: %s" % (self.entry_dir, e)
            self.logger.critical(msg)
            return
        try:
            shutil.rmtree(entry_del_dir)
        except FileNotFoundError:
            pass
        except Exception as e:
            msg = ("Failed to remove cluster entry dir: %s: %s"
                    % (self.entry_dir, e))
            self.logger.warning(msg)
        msg = ("Deleted cluster entry: %s" % object_id)
        self.logger.debug(msg)

class ClusterJournalEntry(ClusterEntry):
    """ Cluster journal entry. """
    def __init__(self, journal_id, journal_dir, timestamp=None, object_uuid=None):
        super(ClusterJournalEntry, self).__init__(journal_dir=journal_dir,
                                                journal_id=journal_id,
                                                _lock_type=JOURNAL_LOCK_TYPE)
        if timestamp or object_uuid:
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

        if timestamp is not None:
            self.timestamp = timestamp
        if object_uuid is not None:
            self.object_uuid = object_uuid

    def __str__(self):
        #x = os.path.getmtime(self.commit_file)
        #return x
        return self.journal_id

    def __repr__(self):
        # We need a string when object is used as dict key!
        return self.__str__()

    def __hash__(self):
        return hash(self.__str__())

    def __eq__(self, other):
        if self.object_uuid:
            return self.object_uuid == other.object_uuid
        return self.object_id == other.object_id

    def __ne__(self, other):
        if self.object_uuid:
            return self.object_uuid != other.object_uuid
        return self.object_id != other.object_id

    def __lt__(self, other):
        return self.__str__() < other.__str__()

    def __gt__(self, other):
        return self.__str__() > other.__str__()

    def add_object_event(self, timestamp):
        object_event_name = "/cluster_journal_%s" % timestamp
        object_event = multiprocessing.Event(object_event_name)
        event_file = "%s/%s.event" % (self.entry_dir, timestamp)
        try:
            filetools.create_file(path=event_file,
                                content=str(timestamp))
        except Exception as e:
            msg = ("Failed to add index event to cluster entry: %s: %s"
                    % (timestamp, e))
            self.logger.critical(msg)
        return object_event

    def get_object_events(self):
        events = []
        event_files = sorted(glob.glob(self.entry_dir + "/[0-9]*.event"))
        for x_file in event_files:
            event_id = os.path.basename(x_file)
            event_id = event_id.split(".")[0]
            object_event_name = "/cluster_journal_%s" % event_id
            object_event = multiprocessing.Event(object_event_name)
            events.append(object_event)
        return events

    @property
    #@entry_lock(write=False)
    def timestamp(self):
        try:
            timestamp = os.stat(self.timestamp_file).st_mtime_ns
        except FileNotFoundError:
            timestamp = 0
        except Exception as e:
            timestamp = 0
            msg = ("Failed to read timestamp from cluster entry: %s: %s"
                    % (self.journal_id, e))
            self.logger.critical(msg)
        return timestamp

    @timestamp.setter
    def timestamp(self, timestamp):
        try:
            if not os.path.exists(self.timestamp_file):
                filetools.touch(self.timestamp_file)
        except FileNotFoundError:
            raise ObjectDeleted()
        except Exception as e:
            msg = ("Failed to add timestamp to cluster entry: %s: %s"
                    % (self.journal_id, e))
            self.logger.critical(msg)
        else:
            os.utime(self.timestamp_file, ns=(timestamp, timestamp))

    @property
    #@entry_lock(write=False)
    def object_id(self):
        try:
            object_id = filetools.read_file(self.object_id_file)
        except FileNotFoundError:
            object_id = None
        except Exception as e:
            object_id = None
            msg = ("Failed to read object ID from cluster entry: %s: %s"
                    % (self.journal_id, e))
            self.logger.critical(msg)
        return object_id

    @object_id.setter
    def object_id(self, object_id):
        try:
            filetools.create_file(path=self.object_id_file,
                                    content=object_id.full_oid)
        except Exception as e:
            msg = ("Failed to add object ID to cluster entry: %s: %s"
                    % (self.journal_id, e))
            self.logger.critical(msg)

    @property
    #@entry_lock(write=False)
    def object_type(self):
        try:
            object_type = filetools.read_file(self.object_type_file)
        except FileNotFoundError:
            object_type = None
        except Exception as e:
            object_type = None
            msg = ("Failed to read object type from cluster entry: %s: %s"
                    % (self.journal_id, e))
            self.logger.critical(msg)
        return object_type

    @object_type.setter
    def object_type(self, object_type):
        try:
            filetools.create_file(path=self.object_type_file,
                                    content=object_type)
        except Exception as e:
            msg = ("Failed to add object type to cluster entry: %s: %s"
                    % (self.journal_id, e))
            self.logger.critical(msg)

    @property
    #@entry_lock(write=False)
    def object_uuid(self):
        try:
            object_uuid = filetools.read_file(self.object_uuid_file)
        except FileNotFoundError:
            object_uuid = None
        except Exception as e:
            object_uuid = None
            msg = ("Failed to read object UUID from cluster entry: %s: %s"
                    % (self.journal_id, e))
            self.logger.critical(msg)
        return object_uuid

    @object_uuid.setter
    def object_uuid(self, object_uuid):
        try:
            filetools.create_file(path=self.object_uuid_file,
                                    content=object_uuid)
        except FileNotFoundError:
            raise ObjectDeleted()
        except Exception as e:
            msg = ("Failed to add object UUID to cluster entry: %s: %s"
                    % (self.journal_id, e))
            self.logger.critical(msg)

    def get_actions(self, node_name=None):
        actions = {}
        file_glob = "%s*" % self.actions_file
        actions_files = sorted(glob.glob(file_glob))
        action_file_re = re.compile('^%s.[0-9]*$' % self.actions_file)
        for x_file in actions_files:
            if not action_file_re.match(x_file):
                continue
            if node_name:
                x_node_file = "%s.%s" % (x_file, node_name)
                if os.path.exists(x_node_file):
                    continue
            try:
                action_data = filetools.read_file(x_file)
            except FileNotFoundError:
                continue
            except Exception as e:
                msg = ("Failed to read index journal from cluster entry: %s: %s"
                        % (self.journal_id, e))
                self.logger.critical(msg)
                continue
            action_data = json.loads(action_data)
            action = action_data['action']
            action_kwargs = action_data['kwargs']
            if node_name:
                def action_committer():
                    x_dir = os.path.dirname(x_node_file)
                    if not os.path.exists(x_dir):
                        raise ObjectDeleted()
                    filetools.touch(x_node_file)
                actions[action] = {
                                    'kwargs'    : action_kwargs,
                                    'committer' : action_committer,
                                }
            else:
                actions[action] = action
        return actions

    def add_action(self, action, **kwargs):
        action_data = {
                        'action'    : action,
                        'kwargs'    : kwargs,
                    }
        action_data = json.dumps(action_data)
        action_file = "%s.%s" % (self.actions_file, time.time_ns())
        try:
            filetools.create_file(path=action_file, content=action_data)
        except Exception as e:
            msg = ("Failed to add action to cluster entry: %s: %s"
                    % (self.journal_id, e))
            self.logger.critical(msg)

    def get_index_journal(self, node_name):
        commit_files = []
        index_journal = []
        file_glob = "%s*" % self.index_journal_file
        index_journal_files = sorted(glob.glob(file_glob))
        journal_file_re = re.compile('^%s.[0-9]*$' % self.index_journal_file)
        for x_file in index_journal_files:
            if not journal_file_re.match(x_file):
                continue
            x_node_file = "%s.%s" % (x_file, node_name)
            if os.path.exists(x_node_file):
                continue
            try:
                x_journal = filetools.read_file(x_file)
            except FileNotFoundError:
                continue
            except Exception as e:
                msg = ("Failed to read index journal from cluster entry: %s: %s"
                        % (self.journal_id, e))
                self.logger.critical(msg)
                continue
            x_journal = json.loads(x_journal)
            index_journal += x_journal
            commit_files.append(x_node_file)
        def journal_committer():
            for x in commit_files:
                x_dir = os.path.dirname(x)
                if not os.path.exists(x_dir):
                    raise ObjectDeleted()
                filetools.touch(x)
        return journal_committer, index_journal

    def add_index_journal(self, index_journal):
        index_journal = json.dumps(index_journal)
        index_journal_file = "%s.%s" % (self.index_journal_file, time.time_ns())
        try:
            filetools.create_file(path=index_journal_file,
                                content=index_journal)
        except Exception as e:
            msg = ("Failed to add index journal to cluster entry: %s: %s"
                    % (self.journal_id, e))
            self.logger.critical(msg)

    def get_acl_journal(self, node_name):
        commit_files = []
        acl_journal = []
        file_glob = "%s*" % self.acl_journal_file
        acl_journal_files = sorted(glob.glob(file_glob))
        journal_file_re = re.compile('^%s.[0-9]*$' % self.acl_journal_file)
        for x_file in acl_journal_files:
            if not journal_file_re.match(x_file):
                continue
            x_node_file = "%s.%s" % (x_file, node_name)
            if os.path.exists(x_node_file):
                continue
            try:
                x_journal = filetools.read_file(x_file)
            except FileNotFoundError:
                continue
            except Exception as e:
                msg = ("Failed to read ACL journal from cluster entry: %s: %s"
                        % (self.journal_id, e))
                self.logger.critical(msg)
                continue
            x_journal = json.loads(x_journal)
            acl_journal += x_journal
            commit_files.append(x_node_file)
        def journal_committer():
            for x in commit_files:
                x_dir = os.path.dirname(x)
                if not os.path.exists(x_dir):
                    raise ObjectDeleted()
                filetools.touch(x)
        return journal_committer, acl_journal

    def add_acl_journal(self, acl_journal):
        acl_journal = json.dumps(acl_journal)
        acl_journal_file = "%s.%s" % (self.acl_journal_file, time.time_ns())
        try:
            filetools.create_file(path=acl_journal_file,
                                content=acl_journal)
        except Exception as e:
            msg = ("Failed to add ACL journal to cluster entry: %s: %s"
                    % (self.journal_id, e))
            self.logger.critical(msg)

    @property
    #@entry_lock(write=False)
    def trash_id(self):
        try:
            trash_id = filetools.read_file(self.trash_id_file)
        except FileNotFoundError:
            trash_id = None
        except Exception as e:
            trash_id = None
            msg = ("Failed to read trash ID from cluster entry: %s: %s"
                    % (self.journal_id, e))
            self.logger.critical(msg)
        return trash_id

    @trash_id.setter
    def trash_id(self, trash_id):
        try:
            filetools.create_file(path=self.trash_id_file,
                                    content=trash_id)
        except Exception as e:
            msg = ("Failed to add trash ID to cluster entry: %s: %s"
                    % (self.journal_id, e))
            self.logger.critical(msg)

    @property
    def deleted_by(self):
        try:
            deleted_by = filetools.read_file(self.deleted_by_file)
        except FileNotFoundError:
            deleted_by = None
        except Exception as e:
            deleted_by = None
            msg = ("Failed to read trash deleted by from cluster entry: %s: %s"
                    % (self.journal_id, e))
            self.logger.critical(msg)
        return deleted_by

    @deleted_by.setter
    def deleted_by(self, deleted_by):
        try:
            filetools.create_file(path=self.deleted_by_file,
                                    content=deleted_by)
        except Exception as e:
            msg = ("Failed to add trash deleted by to cluster entry: %s: %s"
                    % (self.journal_id, e))
            self.logger.critical(msg)

    @property
    #@entry_lock(write=False)
    def object_data(self):
        try:
            object_data = filetools.read_file(self.object_data_file)
        except FileNotFoundError:
            object_data = None
        except Exception as e:
            object_data = None
            msg = ("Failed to read object data from cluster entry: %s: %s"
                    % (self.journal_id, e))
            self.logger.critical(msg)
        return object_data

    @object_data.setter
    def object_data(self, object_data):
        try:
            filetools.create_file(path=self.object_data_file,
                                    content=str(object_data))
        except Exception as e:
            msg = ("Failed to add object data to cluster entry: %s: %s"
                    % (self.journal_id, e))
            self.logger.critical(msg)

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
        self.node_disabled_child = None
        self.all_nodes = []
        self.member_nodes = []
        self.online_nodes = []
        self.processed_journal_entries = {}
        self.nsscache_sync = multiprocessing.get_bool("otpme-nsscache-sync",
                                                    random_name=False,
                                                    init=False)
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
        multiprocessing.cleanup()
        try:
            self.nsscache_sync.close()
        except Exception as e:
            msg = "Failed to close shared bool: %s" % e
            self.logger.warning(msg)
        return super(ClusterDaemon, self).signal_handler(_signal, frame)

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

    def handle_childs(self, reload=False):
        """ Start child processes childs. """
        if self.node_disabled:
            if config.two_node_setup:
                # Wakeup two node handler to notice node disabled status.
                multiprocessing.two_node_setup_event.set()
                multiprocessing.two_node_setup_event.close()
            if self.cluster_in_journal_child:
                if not self.cluster_in_journal_child.is_alive():
                    self.cluster_in_journal_child.join()
                    self.cluster_in_journal_child = None
                    msg = "Stopped cluster process: Cluster in-journal: Node disabled"
                    self.logger.warning(msg)
            if self.cluster_comm_child:
                if not self.cluster_comm_child.is_alive():
                    self.cluster_comm_child.join()
                    self.cluster_comm_child = None
                    msg = "Stopped cluster process: Cluster communication: Node disabled"
                    self.logger.warning(msg)
            if self.interprocess_comm_child:
                # Wakeup interprocess comm process.
                multiprocessing.cluster_out_event.set()
                multiprocessing.cluster_out_event.close()
                if not self.interprocess_comm_child.is_alive():
                    self.interprocess_comm_child.join()
                    self.interprocess_comm_child = None
                    msg = "Stopped cluster process: Cluster IPC: Node disabled"
                    self.logger.warning(msg)
            if config.start_freeradius:
                self.stop_freeradius()
            if self.node_disabled_child:
                if not self.node_disabled_child.is_alive():
                    self.node_disabled_child.join()
                    self.node_disabled_child = None
            if not self.node_disabled_child:
                self.node_disabled_child = multiprocessing.start_process(name=self.name,
                                                    target=self.start_node_disabled_check)
            return

        start_interprocess = True
        if self.interprocess_comm_child:
            if self.interprocess_comm_child.is_alive():
                start_interprocess = False
        start_cluster_comm = True
        if self.cluster_comm_child:
            if self.cluster_comm_child.is_alive():
                start_cluster_comm = False
        start_in_journal = True
        if self.cluster_in_journal_child:
            if self.cluster_in_journal_child.is_alive():
                start_in_journal = False

        log_start_message = False
        if start_interprocess:
            log_start_message = True
        if start_cluster_comm:
            log_start_message = True
        if start_in_journal:
            log_start_message = True

        if self.node_disabled_child:
            if not self.node_disabled_child.is_alive():
                self.node_disabled_child.join()
                self.node_disabled_child = None

        if log_start_message:
            msg = "Starting cluster communication..."
            self.logger.info(msg)

        # Interprocess communication.
        if start_interprocess:
            self.interprocess_comm_child = multiprocessing.start_process(name=self.name,
                                            target=self.start_interprocess_comm)
        # Start cluster communication.
        if start_cluster_comm:
            self.cluster_comm_child = multiprocessing.start_process(name=self.name,
                                            target=self.start_cluster_communication,
                                            target_kwargs={'reload':reload})
        # Start in-journal handler.
        if start_in_journal:
            self.cluster_in_journal_child = multiprocessing.start_process(name=self.name,
                                            target=self.start_in_journal_handler)

    def close_childs(self):
        """ Stop cluster communication childs. """
        log_stop_message = False
        if self.interprocess_comm_child:
            log_stop_message = True
        if self.cluster_comm_child:
            log_stop_message = True
        if self.cluster_in_journal_child:
            log_stop_message = True
        if self.two_node_handler_child:
            log_stop_message = True
        if self.node_disabled_child:
            log_stop_message = True
        if log_stop_message:
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
        if self.node_disabled_child:
            try:
                self.node_disabled_child.terminate()
                self.node_disabled_child.join()
            except Exception as e:
                msg = "Failed to stop node check child: %s" % e
                self.logger.warning(msg)

    def exit_child(self):
        # Wakeup main process to handle childs.
        self.comm_handler.send("clusterd", command="handle_childs")
        multiprocessing.cleanup()
        os._exit(0)

    def start_node_disabled_check(self):
        # Set proctitle.
        new_proctitle = ("%s Cluster node disabled check" % (self.full_name))
        setproctitle.setproctitle(new_proctitle)
        while True:
            if config.daemon_shutdown:
                os._exit(0)
            try:
                clusterd_conn = connections.get("clusterd",
                                                timeout=3,
                                                quiet_autoconnect=True,
                                                compress_request=False)
            except HostDisabled as e:
                time.sleep(1)
                continue
            except Exception as e:
                time.sleep(1)
                continue
            else:
                msg = "Node is enabled again."
                self.logger.info(msg)
                # If the node is enabled again we have to handle sync
                # like a newly joined node (e.g. delete objects on sync).
                filetools.touch(config.node_joined_file)
                # Enable node object.
                self.enable_node()
                # Wakeup main process to start childs.
                self.comm_handler.send("clusterd", command="handle_childs")
                clusterd_conn.close()
                os._exit(0)

    @property
    def host_name(self):
        host_name = config.host_data['name']
        return host_name

    @property
    def host_type(self):
        host_type = config.host_data['type']
        return host_type

    def enable_node(self):
        node_uuid = config.uuid
        node = backend.get_object(uuid=node_uuid)
        if node.enabled:
            return
        node.enable(force=True, verify_acls=False)
        node.acquire_lock(lock_caller="clusterd")
        node._write(cluster=False)
        node.release_lock(lock_caller="clusterd")

    def disable_node(self):
        node_uuid = config.uuid
        node = backend.get_object(uuid=node_uuid)
        if not node.enabled:
            return
        node.disable(force=True, verify_acls=False)
        node.acquire_lock(lock_caller="clusterd")
        node._write(cluster=False)
        node.release_lock(lock_caller="clusterd")

    @property
    def node_disabled(self):
        node_uuid = config.uuid
        node = backend.get_object(uuid=node_uuid)
        if node.enabled:
            return False
        return True

    def get_cluster_out_journal_trash(self):
        journal_dir = TRASH_JOURNAL_DIR
        journal_dirs = sorted(glob.glob(journal_dir + "/*"))
        journal_dirs = [d for d in journal_dirs if not d.endswith(".deleting")]
        journal_entries = []
        for x_dir in journal_dirs:
            journal_id = os.path.basename(x_dir)
            cluster_journal_entry = ClusterJournalEntry(journal_id=journal_id,
                                                        journal_dir=journal_dir)
            try:
                cluster_journal_entry.lock(write=False)
            except ObjectDeleted:
                continue
            journal_entries.append(cluster_journal_entry)
            cluster_journal_entry.release()
        return journal_entries

    def get_cluster_out_journal_last_used(self):
        journal_dir = LAST_USED_JOURNAL_DIR
        journal_dirs = sorted(glob.glob(journal_dir + "/*"))
        journal_dirs = [d for d in journal_dirs if not d.endswith(".deleting")]
        journal_entries = []
        for x_dir in journal_dirs:
            journal_id = os.path.basename(x_dir)
            cluster_journal_entry = ClusterJournalEntry(journal_id=journal_id,
                                                        journal_dir=journal_dir)
            if not cluster_journal_entry.committed:
                continue
            try:
                cluster_journal_entry.lock(write=False)
            except ObjectDeleted:
                continue
            journal_entries.append(cluster_journal_entry)
            cluster_journal_entry.release()
        return journal_entries

    def get_cluster_out_journal(self):
        journal_dir = OBJECTS_JOURNAL_DIR
        journal_dirs = glob.glob(journal_dir + "/*")
        journal_dirs = [d for d in journal_dirs if not d.endswith(".deleting")]
        journal_entries = {}
        journal_entries_sorted = []
        for x_dir in journal_dirs:
            journal_id = os.path.basename(x_dir)
            cluster_journal_entry = ClusterJournalEntry(journal_id=journal_id,
                                                        journal_dir=journal_dir)
            if not cluster_journal_entry.committed:
                continue
            try:
                cluster_journal_entry.lock(write=False)
            except ObjectDeleted:
                continue
            try:
                try:
                    processed_timestamp = self.processed_journal_entries[cluster_journal_entry.journal_id]
                except KeyError:
                    pass
                else:
                    if cluster_journal_entry.timestamp == processed_timestamp:
                        continue
                try:
                    object_type = cluster_journal_entry.object_type
                except ObjectDeleted:
                    continue
                if not object_type:
                    continue
                try:
                    object_list = journal_entries[object_type]
                except KeyError:
                    object_list = []
                    journal_entries[object_type] = object_list
            finally:
                cluster_journal_entry.release()
            object_list.append(cluster_journal_entry)
        for object_type in config.object_add_order:
            try:
                object_list = journal_entries[object_type]
            except KeyError:
                object_list = []
            journal_entries_sorted += object_list
        journal_entries_sorted += self.get_cluster_out_journal_trash()
        return journal_entries_sorted

    def get_cluster_in_journal(self):
        journal_files = sorted(glob.glob(CLUSTER_IN_JOURNAL_DIR + "/[0-9]*"))
        return journal_files

    def clean_cluster_out_journal(self):
        journal_entries = self.get_cluster_out_journal()
        journal_entries += self.get_cluster_out_journal_last_used()
        for cluster_journal_entry in journal_entries:
            events = cluster_journal_entry.get_object_events()
            for object_event in events:
                object_event.set()
                object_event.unlink()
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
            multiprocessing.online_nodes.pop(node_name)
        except KeyError:
            pass
        try:
            multiprocessing.member_nodes.pop(node_name)
        except KeyError:
            pass
        if self.node_conn:
            self.node_conn.close()
            self.node_conn = None
        self.calc_quorum()
        # Wakeup cluster out event handler to re-process cluster journal entries.
        if not multiprocessing.cluster_out_event:
            return
        multiprocessing.cluster_out_event.set()

    def node_disconnect(self, node_name):
        try:
            multiprocessing.ready_nodes.pop(node_name)
        except KeyError:
            pass
        try:
            multiprocessing.peer_nodes_set_online.pop(node_name)
        except KeyError:
            pass
        self.node_conn = None
        # Wakeup cluster out event handler to re-process cluster journal entries.
        if not multiprocessing.cluster_out_event:
            return
        multiprocessing.cluster_out_event.set()

    def get_conn_event_name(self, node_name):
        conn_even_name = "/cjournal-event-%s" % node_name
        return conn_even_name

    def start_initial_sync(self, node_name):
        """ Start initial sync of sessions etc.. """
        while True:
            if config.daemon_shutdown:
                os._exit(0)
            if self.node_disabled:
                self.exit_child()
            try:
                clusterd_conn = self.get_clusterd_connection(node_name)
            except Exception as e:
                msg = ("Failed to get initial sync connection: %s: %s"
                        % (node_name, e))
                self.logger.warning(msg)
                time.sleep(1)
                continue
            sync_finished = False
            # Sync data objects.
            msg = "Starting data sync with node: %s" % node_name
            self.logger.info(msg)
            skip_deletions = True
            if os.path.exists(config.node_joined_file):
                skip_deletions = False
            try:
                clusterd_conn.sync(skip_deletions=skip_deletions)
            except Exception as e:
                msg = "Failed to sync with node: %s: %s" % (node_name, e)
                self.logger.warning(msg)
                time.sleep(1)
                #config.raise_exception()
            else:
                msg = "Data sync finished with node: %s" % node_name
                self.logger.info(msg)
                sync_finished = True
            try:
                clusterd_conn.sync_last_used()
            except Exception as e:
                msg = "Failed to sync last used times with node: %s: %s" % (node_name, e)
                self.logger.warning(msg)
                time.sleep(1)
                #config.raise_exception()
            else:
                msg = "Data sync finished with node: %s" % node_name
                self.logger.info(msg)
                sync_finished = True
            # Sync trash objects.
            msg = "Starting trash sync with node: %s" % node_name
            self.logger.info(msg)
            try:
                clusterd_conn.sync_trash()
            except Exception as e:
                msg = "Failed to sync trash with node: %s: %s" % (node_name, e)
                self.logger.warning(msg)
                time.sleep(1)
                #config.raise_exception()
            else:
                msg = "Trash sync finished with node: %s" % node_name
                self.logger.info(msg)
                sync_finished = True
            if sync_finished:
                break

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
            if self.node_disabled:
                self.exit_child()
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
            if self.node_disabled:
                self.exit_child()
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
                    if config.debug_level() > 2:
                        if not quiet:
                            msg = ("Got cluster vote from node: %s: %s"
                                    % (node_name, node_vote))
                            self.logger.debug(msg)
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
        if len(node_scores_sorted) == 0:
            msg = "Cannot get master node: No node votes."
            raise MasterNodeElectionFailed(msg)
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
        # Check for configured required quorum.
        own_site = backend.get_object(uuid=config.site_uuid)
        if own_site.required_votes:
            required_votes = own_site.required_votes
        else:
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
        if node_vote != 0:
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
        # If admin set required votes to 1 and we have no member
        # nodes we have to enable two node setup.
        own_site = backend.get_object(uuid=config.site_uuid)
        if own_site.required_votes == 1:
            if len(multiprocessing.member_nodes) == 0:
                config.two_node_setup = True
                return

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
            if not config.one_node_setup:
                msg = "Switched to one-node-setup."
                self.logger.info(msg)
            config.one_node_setup = True
            config.two_node_setup = False
        elif len(enabled_nodes) == 2:
            if not config.two_node_setup:
                msg = "Switched to two-node-setup."
                self.logger.info(msg)
            config.one_node_setup = False
            config.two_node_setup = True
        else:
            if config.one_node_setup or config.two_node_setup:
                msg = "Switched to multi-node-setup."
                self.logger.info(msg)
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
            self.check_nsscache_sync()

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
            if not proc.is_alive():
                self.close_node_check_connection(node_name)
                try:
                    multiprocessing.node_connections.pop(node_name)
                except KeyError:
                    pass
            try:
                proc = self.node_write_connections[node_name]
            except:
                continue
            if not proc.is_alive():
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
            if self.node_disabled:
                self.exit_child()
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

    def get_clusterd_connection(self, node_name, timeout=60, quiet=True):
        socket_uri = stuff.get_daemon_socket("clusterd", node_name)
        try:
            clusterd_conn = connections.get("clusterd",
                                            timeout=timeout,
                                            socket_uri=socket_uri,
                                            quiet_autoconnect=quiet,
                                            compress_request=False)
        except HostDisabled as e:
            msg = "Failed to get cluster connection: %s" % e
            self.logger.warning(msg)
            # Check if node is disabled on master node.
            try:
                master_node_conn = connections.get("clusterd",
                                                timeout=3,
                                                quiet_autoconnect=True,
                                                compress_request=False)
            except HostDisabled as e:
                self.disable_node()
            else:
                master_node_conn.close()
            raise
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
            except NoClusterService:
                if not self.node_offline:
                    self.node_leave(node_name)
                    self.node_offline = True
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
            self.node_leave(node_name)
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

    def do_master_node_sync(self, master_node, sync_last_used=False):
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
            if self.node_disabled:
                self.exit_child()
            skip_deletions = True
            run_nsscache_sync = False
            if os.path.exists(config.node_joined_file):
                skip_deletions = False
                run_nsscache_sync = True
            # Run initial sync.
            try:
                sync_status = command_handler.do_sync(sync_type="objects",
                                                    realm=config.realm,
                                                    site=config.site,
                                                    max_tries=10,
                                                    sync_last_used=sync_last_used,
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
                    return sync_status
                time.sleep(1)
                continue
            # Run nsscache sync.
            if run_nsscache_sync:
                try:
                    sync_status = command_handler.do_sync(sync_type="nsscache",
                                                        realm=config.realm,
                                                        site=config.site)
                except Exception as e:
                    sync_status = False
                    msg = "Initial sync of nsscache failed: %s" % e
                    self.logger.warning(msg)
                if sync_status is False:
                    msg = "Initial nsscache sync failed."
                    self.logger.warning(msg)
                    return sync_status
            #filetools.delete(config.node_joined_file)
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
        from otpme.lib.classes.command_handler import CommandHandler
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

        wait_for_second_node = False
        if config.two_node_setup:
            wait_for_second_node = True
        quorum_check_interval = 3
        quorum_message_sent = False
        second_node_wait_timeout = 0
        while True:
            if config.daemon_shutdown:
                os._exit(0)
            if self.node_disabled:
                self.exit_child()
            # Handle node connections.
            self.handle_node_connections()
            # Handle nsscache sync.
            if self.nsscache_sync.value:
                # Skip nsscache sync if last object creation was within the last 30 seconds.
                min_seconds = 10
                now = time.time()
                data_revision = config.get_data_revision()
                age = now - data_revision
                if age > min_seconds:
                    try:
                        command_handler = CommandHandler()
                        command_handler.start_sync(sync_type="nsscache")
                    except Exception as e:
                        msg = "Failed to trigger nsscache sync: %s" % e
                        self.logger.warning(msg)
                    else:
                        msg = "Triggered nsscache sync."
                        self.logger.info(msg)
                        self.nsscache_sync.value = False

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
                                time.sleep(0.1)
                                continue
                            break
                        sync_status = self.do_master_node_sync(master_node,
                                                            sync_last_used=True)
                        if sync_status is not None:
                            sync_status = self.do_master_node_sync(master_node,
                                                                sync_last_used=True)
                        if sync_status is False:
                            continue
                        if self.host_name not in multiprocessing.master_sync_done:
                            multiprocessing.master_sync_done.append(self.host_name)
                    else:
                        multiprocessing.master_sync_done.append(self.host_name)
                    # Start initial data sync.
                    self.start_initial_sync(master_node)
                    # Remove new joined node file.
                    filetools.delete(config.node_joined_file)

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
                msg = "Waiting for cluster in-journal to be processed..."
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
        all_entries += self.get_cluster_out_journal_last_used()
        for cluster_journal_entry in all_entries:
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

    def set_node_online(self, node_name):
        """ Set node online. """
        # Check if node exists and is enabled.
        result = backend.search(object_type="node",
                            attribute="name",
                            value=node_name,
                            realm=config.realm,
                            site=config.site,
                            return_type="instance")
        if not result:
            msg = "Unknown node: %s" % node_name
            self.logger.warning(msg)
            return False
        node = result[0]
        if not node.enabled:
            return False
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
        """ Start cluster in-journal handler. """
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
            if self.node_disabled:
                self.exit_child()

            try:
                self.handle_cluster_in_journal()
            except Exception as e:
                msg = "Failed to handle cluster in-journal: %s" % e
                self.logger.critical(msg)
                #config.raise_exception()

    def handle_cluster_in_journal(self):
        cluster_journal_files = self.get_cluster_in_journal()
        for journal_file in cluster_journal_files:
            object_data = filetools.read_file(path=journal_file,
                                            compression="lz4")
            object_data = json.loads(object_data)

            action = object_data['action']
            if action == "write":
                object_id = object_data['object_id']
                object_id = oid.get(object_id)
                if object_id.object_type != "user":
                    try:
                        os.remove(journal_file)
                    except Exception as e:
                        msg = ("Failed to delete cluster in-journal file: %s: %s"
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
                        msg = ("Failed to delete cluster in-journal file: %s: %s"
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

            if action == "delete":
                object_id = object_data['object_id']
                object_id = oid.get(object_id)
                object_uuid = object_data['object_uuid']
                x_uuid = backend.get_uuid(object_id)
                if object_uuid == x_uuid:
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
                os.remove(journal_file)
            except Exception as e:
                msg = ("Failed to delete cluster in-journal file: %s: %s"
                        % (journal_file, e))
                self.logger.critical(msg)

    def check_nsscache_sync(self):
        """ Check if nsscache sync is needed. """
        if is_running(config.nsscache_pidfile):
            return
        data_revision = config.get_data_revision()
        synced_data_revision = nsscache.get_last_synced_revision()
        if synced_data_revision == data_revision:
            return
        min_seconds = 15
        now = time.time()
        age = now - data_revision
        if age < min_seconds:
            return
        self.nsscache_sync.value = True

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
            if self.node_disabled:
                self.exit_child()

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
            if self.node_disabled:
                self.exit_child()

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
            if self.node_disabled:
                self.exit_child()

            start_over= False
            if self.node_conn is None:
                node_conn = self.get_node_connection(node_name)
                if not node_conn:
                    continue

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
                #config.raise_exception()

            if start_over:
                continue

            if not config.master_node:
                continue

            self.check_nsscache_sync()

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
                        self.node_disconnect(node_name)
                        msg = "Failed to get data revision: %s: %s" % (node_name, e)
                        self.logger.warning(msg)
                        return True
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
                            try:
                                self.node_conn.write(object_id.full_oid,
                                                    object_config,
                                                    full_data_update=True,
                                                    full_index_update=True)
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
            finally:
                multiprocessing.pause_writes.remove(self.pid)

            # Add node to cluster member nodes.
            self.member_candidate = False
            multiprocessing.member_nodes[node_name] = True
            msg = "Node joined the cluster: %s" % node_name
            self.logger.info(msg)

    def get_journal_entries_to_process(self, node_name, last_used=False):
        entries_to_process = []
        if last_used:
            all_entries = self.get_cluster_out_journal_last_used()
        else:
            all_entries = self.get_cluster_out_journal()
        for cluster_journal_entry in all_entries:
            try:
                if not cluster_journal_entry.committed:
                    break
                try:
                    cluster_journal_entry.lock(write=False)
                except ObjectDeleted:
                    continue
                try:
                    if node_name in cluster_journal_entry.get_nodes():
                        # Check if object was written to member nodes.
                        if self.check_member_nodes(cluster_journal_entry):
                            # Check if object was written to all online nodes.
                            self.check_online_nodes(cluster_journal_entry)
                        continue
                finally:
                    cluster_journal_entry.release()
                entries_to_process.append(cluster_journal_entry)
            except ObjectDeleted:
                pass
        return entries_to_process

    def process_cluster_journal(self, node_name):
        """ Process cluster journal. """
        written_entries = []
        while True:
            entries_to_process = self.get_journal_entries_to_process(node_name)
            if not entries_to_process:
                break
            written_entries = self.process_cluster_out_journal(node_name, entries_to_process)

        self.process_last_used(node_name)

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

    def process_cluster_out_journal(self, node_name, entries_to_process):
        """ Process cluster journal. """
        msg = "Handling cluster out journal: %s" % node_name
        self.logger.debug(msg)
        written_entries = []
        unsync_status_set = False
        for cluster_journal_entry in entries_to_process:
            node_conn = self.node_conn
            if node_conn is None:
                msg = "No node connection."
                raise ProcessingFailed(msg)
            try:
                object_id = cluster_journal_entry.object_id
                if object_id:
                    object_id = oid.get(object_id)
                processed_timestamp = cluster_journal_entry.timestamp
                object_uuid = cluster_journal_entry.object_uuid
                actions = cluster_journal_entry.get_actions(node_name)
                object_written = False
                for action in actions:
                    action_kwargs = actions[action]['kwargs']
                    action_committer = actions[action]['committer']
                    # Mark node as out of sync (tree objects).
                    if config.master_node:
                        if object_id:
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
                        if object_written:
                            action_committer()
                        else:
                            object_config = backend.read_config(object_id)
                            # Remove outdated cluster journal entry.
                            if not object_config:
                                try:
                                    cluster_journal_entry.add_node(node_name)
                                except ObjectDeleted:
                                    pass
                                if self.check_member_nodes(cluster_journal_entry):
                                    self.check_online_nodes(cluster_journal_entry)
                                continue
                            object_config = object_config.decrypt(config.master_key)
                            object_checksum = backend.get_checksum(object_id)
                            object_last_used = backend.get_last_used(object_uuid)
                            acl_journal_committer, \
                            acl_journal = cluster_journal_entry.get_acl_journal(node_name)
                            index_journal_committer, \
                            index_journal = cluster_journal_entry.get_index_journal(node_name)
                            failed_nodes = cluster_journal_entry.get_failed_nodes()
                            if object_id.object_type in config.flat_object_types:
                                acl_journal = None
                                index_journal = None
                                use_acl_journal = False
                                use_index_journal = False
                                full_acl_update = True
                                full_index_update = True
                            elif node_name in failed_nodes:
                                acl_journal = None
                                index_journal = None
                                use_acl_journal = False
                                use_index_journal = False
                                full_acl_update = True
                                full_index_update = True
                            else:
                                use_acl_journal = True
                                use_index_journal = True
                                full_acl_update = False
                                full_index_update = False
                            try:
                                write_status = node_conn.write(object_id.full_oid,
                                                            object_config,
                                                            acl_journal=acl_journal,
                                                            index_journal=index_journal,
                                                            use_acl_journal=use_acl_journal,
                                                            use_index_journal=use_index_journal,
                                                            use_ldif_journal=False,
                                                            full_acl_update=full_acl_update,
                                                            full_index_update=full_index_update,
                                                            full_ldif_update=True,
                                                            full_data_update=True,
                                                            object_uuid=object_uuid,
                                                            last_used=object_last_used)
                            except (ConnectionTimeout, ConnectionError, ConnectionQuit) as e:
                                #self.node_leave(node_name)
                                self.node_disconnect(node_name)
                                msg = ("Failed to send object: %s: %s: %s"
                                        % (node_name, object_id, e))
                                self.logger.warning(msg)
                                cluster_journal_entry.add_failed_node(node_name)
                                #self.check_member_nodes(cluster_journal_entry)
                                raise ProcessingFailed(msg)
                            except Exception as e:
                                #self.node_leave(node_name)
                                self.node_disconnect(node_name)
                                msg = ("Error sending object: %s: %s: %s"
                                        % (node_name, object_id, e))
                                self.logger.warning(msg)
                                cluster_journal_entry.add_failed_node(node_name)
                                #self.check_member_nodes(cluster_journal_entry)
                                #config.raise_exception()
                                raise ProcessingFailed(msg)
                            if write_status != "done":
                                cluster_journal_entry.add_failed_node(node_name)
                                continue
                            msg = ("Written object to node: %s: %s (%s)"
                                    % (node_name, object_id, object_checksum))
                            self.logger.debug(msg)
                            try:
                                index_journal_committer()
                            except ObjectDeleted:
                                pass
                            try:
                                acl_journal_committer()
                            except ObjectDeleted:
                                pass
                            try:
                                action_committer()
                            except ObjectDeleted:
                                pass
                            try:
                                cluster_journal_entry.add_node(node_name)
                            except ObjectDeleted:
                                pass
                            object_written = True
                            written_entries.append(object_id)
                    # Rename object on peer.
                    if action == "rename":
                        old_object_id = action_kwargs['old_object_id']
                        old_object_id = oid.get(old_object_id)
                        new_object_id = action_kwargs['new_object_id']
                        new_object_id = oid.get(new_object_id)
                        try:
                            rename_status = node_conn.rename(object_id=old_object_id.full_oid,
                                                            new_object_id=new_object_id.full_oid)
                        except (ConnectionTimeout, ConnectionError, ConnectionQuit) as e:
                            #self.node_leave(node_name)
                            self.node_disconnect(node_name)
                            msg = ("Failed to rename object: %s: %s: %s"
                                    % (node_name, object_id, e))
                            self.logger.warning(msg)
                            #self.check_member_nodes(cluster_journal_entry)
                            raise ProcessingFailed(msg)
                        except Exception as e:
                            #config.raise_exception()
                            #self.node_leave(node_name)
                            self.node_disconnect(node_name)
                            msg = ("Failed to rename object: %s: %s: %s"
                                    % (node_name, object_id, e))
                            self.logger.warning(msg)
                            #self.check_member_nodes(cluster_journal_entry)
                            raise ProcessingFailed(msg)
                        if rename_status != "done":
                            continue
                        msg = ("Renamed object on node: %s: %s: %s"
                                % (node_name, old_object_id, new_object_id))
                        self.logger.debug(msg)
                        try:
                            action_committer()
                        except ObjectDeleted:
                            pass
                        try:
                            cluster_journal_entry.add_node(node_name)
                        except ObjectDeleted:
                            pass
                    # Delete object on peer.
                    if action == "delete":
                        try:
                            del_status = node_conn.delete(object_id.full_oid, object_uuid)
                        except (ConnectionTimeout, ConnectionError, ConnectionQuit) as e:
                            #self.node_leave(node_name)
                            self.node_disconnect(node_name)
                            msg = ("Failed to delete object: %s: (%s) %s"
                                    % (object_id, node_name, e))
                            self.logger.warning(msg)
                            #self.check_member_nodes(cluster_journal_entry)
                            raise ProcessingFailed(msg)
                        except Exception as e:
                            #self.node_leave(node_name)
                            self.node_disconnect(node_name)
                            msg = ("Error deleting object: %s: (%s) %s"
                                    % (object_id, node_name, e))
                            self.logger.warning(msg)
                            #self.check_member_nodes(cluster_journal_entry)
                            raise ProcessingFailed(msg)
                        if del_status != "done":
                            continue
                        msg = ("Deleted object on node: %s: %s"
                                % (node_name, object_id))
                        self.logger.debug(msg)
                        try:
                            action_committer()
                        except ObjectDeleted:
                            pass
                        try:
                            cluster_journal_entry.add_node(node_name)
                        except ObjectDeleted:
                            pass
                    # Write trash object to peer.
                    if action == "trash_write":
                        object_data = cluster_journal_entry.object_data
                        # Remove outdated cluster journal entry.
                        if not object_data:
                            try:
                                cluster_journal_entry.add_node(node_name)
                            except ObjectDeleted:
                                pass
                            if self.check_member_nodes(cluster_journal_entry):
                                self.check_online_nodes(cluster_journal_entry)
                            continue
                        trash_id = cluster_journal_entry.trash_id
                        deleted_by = cluster_journal_entry.deleted_by
                        try:
                            trash_write_status = node_conn.trash_write(trash_id=trash_id,
                                                                    object_id=object_id.full_oid,
                                                                    object_data=object_data,
                                                                    deleted_by=deleted_by)
                        except (ConnectionTimeout, ConnectionError, ConnectionQuit) as e:
                            #self.node_leave(node_name)
                            self.node_disconnect(node_name)
                            msg = ("Failed to send trash object: %s: %s: %s: %s"
                                    % (node_name, trash_id, object_id, e))
                            self.logger.warning(msg)
                            #self.check_member_nodes(cluster_journal_entry)
                            raise ProcessingFailed(msg)
                        except Exception as e:
                            #self.node_leave(node_name)
                            self.node_disconnect(node_name)
                            msg = ("Error sending trash object: %s: %s: %s: %s"
                                    % (node_name, trash_id, object_id, e))
                            self.logger.warning(msg)
                            #self.check_member_nodes(cluster_journal_entry)
                            raise ProcessingFailed(msg)
                        if trash_write_status != "done":
                            continue
                        msg = ("Written trash object to node: %s: %s: %s"
                                % (node_name, trash_id, object_id))
                        self.logger.debug(msg)
                        try:
                            action_committer()
                        except ObjectDeleted:
                            pass
                        try:
                            cluster_journal_entry.add_node(node_name)
                        except ObjectDeleted:
                            pass
                        written_entries.append(object_id)
                    # Delete trash object on peer.
                    if action == "trash_delete":
                        trash_id = cluster_journal_entry.trash_id
                        try:
                            trash_del_status = node_conn.trash_delete(trash_id)
                        except (ConnectionTimeout, ConnectionError, ConnectionQuit) as e:
                            #self.node_leave(node_name)
                            self.node_disconnect(node_name)
                            msg = ("Failed to delete trash object: %s: %s: %s"
                                    % (node_name, trash_id, e))
                            self.logger.warning(msg)
                            #self.check_member_nodes(cluster_journal_entry)
                            raise ProcessingFailed(msg)
                        except Exception as e:
                            #self.node_leave(node_name)
                            self.node_disconnect(node_name)
                            msg = ("Error deleting trash object: %s: %s: %s"
                                    % (node_name, trash_id, e))
                            self.logger.warning(msg)
                            #self.check_member_nodes(cluster_journal_entry)
                            #config.raise_exception()
                            raise ProcessingFailed(msg)
                        if trash_del_status != "done":
                            continue
                        msg = ("Deleted trash object on node: %s (%s)"
                                % (node_name, trash_id))
                        self.logger.debug(msg)
                        try:
                            action_committer()
                        except ObjectDeleted:
                            pass
                        try:
                            cluster_journal_entry.add_node(node_name)
                        except ObjectDeleted:
                            pass
                    # Send trash empty request to peer.
                    if action == "trash_empty":
                        try:
                            trash_empty_status = node_conn.trash_empty()
                        except (ConnectionTimeout, ConnectionError, ConnectionQuit) as e:
                            #self.node_leave(node_name)
                            self.node_disconnect(node_name)
                            msg = ("Failed to send trash empty request: %s: %s"
                                    % (node_name, e))
                            self.logger.warning(msg)
                            #self.check_member_nodes(cluster_journal_entry)
                            raise ProcessingFailed(msg)
                        except Exception as e:
                            #self.node_leave(node_name)
                            self.node_disconnect(node_name)
                            msg = ("Error sending trash empty request: %s: %s"
                                    % (node_name, e))
                            self.logger.warning(msg)
                            #self.check_member_nodes(cluster_journal_entry)
                            raise ProcessingFailed(msg)
                        if trash_empty_status != "done":
                            continue
                        msg = ("Trash emptied on node: %s" % (node_name))
                        self.logger.debug(msg)
                        try:
                            action_committer()
                        except ObjectDeleted:
                            pass
                        try:
                            cluster_journal_entry.add_node(node_name)
                        except ObjectDeleted:
                            pass
                # Check if object was written to member nodes.
                member_nodes_check = self.check_member_nodes(cluster_journal_entry,
                                                        timestamp=processed_timestamp,
                                                        cache=True)
                if member_nodes_check:
                    # Check if object was written to all online nodes.
                    self.check_online_nodes(cluster_journal_entry)
            except ObjectDeleted:
                pass

        return written_entries

    def process_last_used(self, node_name):
        """ Process cluster journal. """
        last_used_times = {}
        last_used_journal_entries = self.get_journal_entries_to_process(node_name, last_used=True)
        for cluster_journal_entry in last_used_journal_entries:
            node_conn = self.node_conn
            if node_conn is None:
                msg = "No node connection."
                raise ProcessingFailed(msg)
            try:
                object_id = cluster_journal_entry.object_id
                object_id = oid.get(object_id)
                object_type = object_id.object_type
                object_uuid = cluster_journal_entry.object_uuid
                # We need to read action last because it will throw
                # ObjectDeleted exception if the cluster entry was deleted.
                actions = cluster_journal_entry.get_actions(node_name)
                for action in actions:
                    action_committer = actions[action]['committer']
                    if action != "last_used_write":
                        msg = "Unknown last used command: %s" % action
                        self.logger.warning(msg)
                        try:
                            cluster_journal_entry.add_node(node_name)
                        except ObjectDeleted:
                            pass
                        try:
                            action_committer()
                        except ObjectDeleted:
                            pass
                        if self.check_member_nodes(cluster_journal_entry):
                            self.check_online_nodes(cluster_journal_entry)
                        continue
                    try:
                        last_used = float(cluster_journal_entry.object_data)
                    except TypeError:
                        msg = "Broken last used clusterentry: %s" % cluster_journal_entry
                        self.logger.warning(msg)
                        try:
                            cluster_journal_entry.add_node(node_name)
                        except ObjectDeleted:
                            pass
                        try:
                            action_committer()
                        except ObjectDeleted:
                            pass
                        if self.check_member_nodes(cluster_journal_entry):
                            self.check_online_nodes(cluster_journal_entry)
                        continue
                    try:
                        last_used_objects = last_used_times[object_type]
                    except KeyError:
                        last_used_objects = {}
                        last_used_times[object_type] = last_used_objects
                    last_used_objects[object_uuid] = last_used
                    try:
                        action_committer()
                    except ObjectDeleted:
                        pass
                    try:
                        cluster_journal_entry.add_node(node_name)
                    except ObjectDeleted:
                        continue
                    # Check if object was written to member nodes.
                    if self.check_member_nodes(cluster_journal_entry):
                        # Check if object was written to all online nodes.
                        self.check_online_nodes(cluster_journal_entry)
            except ObjectDeleted:
                pass

        for object_type in last_used_times:
            last_used_objects= last_used_times[object_type]
            try:
                last_used_write_status = node_conn.last_used_write(object_type, last_used_objects)
            except (ConnectionTimeout, ConnectionError, ConnectionQuit) as e:
                self.node_disconnect(node_name)
                msg = ("Failed to send last used times: %s: %s: %s"
                        % (node_name, object_type, e))
                self.logger.warning(msg)
                #self.check_member_nodes(cluster_journal_entry)
                raise ProcessingFailed(msg)
            except Exception as e:
                #self.node_leave(node_name)
                self.node_disconnect(node_name)
                msg = ("Error sending last used times: %s: %s: %s"
                        % (node_name, object_type, e))
                self.logger.warning(msg)
                #self.check_member_nodes(cluster_journal_entry)
                raise ProcessingFailed(msg)
            if last_used_write_status != "done":
                continue
            msg = ("Sent last used times to node: %s: %s"
                    % (node_name, object_type))
            self.logger.debug(msg)

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
            self.node_disconnect(node_name)
            msg = ("Failed to unset cluster sync state: %s: %s"
                    % (node_name, e))
            self.logger.warning(msg)
            raise
        except Exception as e:
            self.node_disconnect(node_name)
            msg = ("Error unsetting cluster sync state: %s: %s"
                    % (node_name, e))
            self.logger.warning(msg)
            raise

    def check_online_nodes(self, cluster_journal_entry):
        org_timestamp = cluster_journal_entry.timestamp
        try:
            cluster_journal_entry.lock(write=True)
        except ObjectDeleted:
            return
        try:
            entry_nodes = cluster_journal_entry.get_nodes()
            online_nodes = sorted(multiprocessing.online_nodes)
            online_nodes_in_sync = True
            for node_name in online_nodes:
                if node_name in entry_nodes:
                    continue
                online_nodes_in_sync = False
            if not online_nodes_in_sync:
                return
            # Delete journal entries must be synced to all enabled nodes
            # even offline ones.
            all_nodes_in_sync = True
            actions = cluster_journal_entry.get_actions()
            if "delete" in actions \
            or "trash_delete" in actions:
                enabled_nodes = list(self.get_enabled_nodes())
                for node_name in enabled_nodes:
                    if node_name == self.host_name:
                        continue
                    if node_name in entry_nodes:
                        continue
                    all_nodes_in_sync = False
            if not all_nodes_in_sync:
                return
            events = cluster_journal_entry.get_object_events()
            for object_event in events:
                object_event.set()
                object_event.unlink()
            if org_timestamp != cluster_journal_entry.timestamp:
                return
            try:
                cluster_journal_entry.delete()
            except ObjectDeleted:
                pass
            try:
                self.processed_journal_entries.pop(cluster_journal_entry.journal_id)
            except KeyError:
                pass
        finally:
            cluster_journal_entry.release()

    def check_member_nodes(self, cluster_journal_entry, timestamp=None, cache=False):
        if timestamp is None:
            timestamp = cluster_journal_entry.timestamp
        try:
            cluster_journal_entry.lock(write=True)
        except ObjectDeleted:
            return True
        try:
            entry_nodes = sorted(cluster_journal_entry.get_nodes())
            member_nodes = sorted(multiprocessing.member_nodes)
            written_nodes = 0
            min_written_nodes = 1
            member_nodes_in_sync = True
            for node_name in member_nodes:
                if node_name in entry_nodes:
                    written_nodes += 1
                    continue
                member_nodes_in_sync = False
            if config.two_node_setup:
                min_written_nodes = 0
            if written_nodes >= min_written_nodes:
                member_nodes_in_sync = True
            if not member_nodes_in_sync:
                return False
            events = cluster_journal_entry.get_object_events()
            for object_event in events:
                object_event.set()
                #object_event.unlink()
            if timestamp != cluster_journal_entry.timestamp:
                return False
            if cache:
                self.processed_journal_entries[cluster_journal_entry.journal_id] = timestamp
        finally:
            cluster_journal_entry.release()
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
        from otpme.lib.freeradius.utils import start
        from otpme.lib.freeradius.utils import status
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
        from otpme.lib.freeradius.utils import stop
        from otpme.lib.freeradius.utils import status
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
        # Set logger.
        self.logger = config.logger
        # Set node vote to (1 - daemon start time) (e.g.first started
        # node gets master node if all nodes have the same data
        # revision.
        config.node_vote = 1 - time.time()
        # Initially we dont have quorum.
        config.cluster_quorum = False
        multiprocessing.cluster_quorum.clear()
        # On daemon reload we have to keep master node status.
        if reload:
            if master_node:
                sync_time = time.time()
                config.touch_node_sync_file(sync_time)
            else:
                config.remove_node_sync_file()
        else:
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

        # Make sure cluster in-journal is clean on daemon start.
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

        if self.node_disabled:
            msg = "Not starting cluster processes: Node disabled"
            self.logger.warning(msg)

        self.nsscache_sync.init()

        while True:
            if config.daemon_shutdown:
                os._exit(0)

            # Handle child processes.
            self.handle_childs(reload=reload)

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
                self.daemon_startup.value = False
