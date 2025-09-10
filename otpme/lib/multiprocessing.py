# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import sys
import pwd
import grp
import mmap
import psutil
import signal
import posix_ipc
import threading
#import functools
import setproctitle
import multiprocessing
from multiprocessing.managers import SyncManager

try:
    import ujson as json
except:
    import json

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import filetools

from otpme.lib.exceptions import *

shared_objects = {}
FORK_LOCK = "fork"
LOCK_TYPE = "multiprocessing"
MODULE_PATH = "otpme.lib.multiprocessing"

REGISTER_BEFORE = []
REGISTER_AFTER = ["otpme.lib.encoding.base"]

pid = None
## Process name.
#proc_name = None
#proc_thread_id = None
# Posix message queues to close on exit.
message_queues = []
# Posix semaphores to close on exit.
posix_semaphores = {}
# Python multiprocessing manager to use. This is only used within otpme-agent.
manager = None

# Clusterd events.
cluster_in_event = None
cluster_out_event = None
#cluster_lock_event = None
# Shared dict to handle objects to sync with peers.
cluster_votes = None
# Cluster locks acquired by clusterd.
cluster_read_locks = {}
cluster_write_locks = {}

# PID of the current process.
def register():
    """ Register module. """
    from otpme.lib import locking
    locking.register_lock_type(LOCK_TYPE, module=__file__)

def register_module_var(v_name, v_type):
    """ Register variable. """
    module = sys.modules[MODULE_PATH]
    setattr(module, v_name, v_type)

def register_shared_dict(name, clear=False, locking=False, pickle=False):
    """ Register shared dict. """
    global shared_objects
    if name in shared_objects:
        msg = "Shared dict already registered: %s" % name
        raise OTPmeException(msg)
    shared_objects[name] = {
                            'type'      : 'dict',
                            'clear'     : clear,
                            'locking'   : locking,
                            'pickle'    : pickle,
                        }
    fake_shared_dict = SharedDict(name)
    register_module_var(name, fake_shared_dict)

def register_shared_list(name, clear=False, locking=False, pickle=False):
    """ Register shared list. """
    global shared_objects
    if name in shared_objects:
        msg = "Shared list already registered: %s" % name
        raise OTPmeException(msg)
    shared_objects[name] = {
                            'type'      : 'list',
                            'clear'     : clear,
                            'locking'   : locking,
                            'pickle'    : pickle,
                        }
    fake_shared_list = SharedList(name)
    register_module_var(name, fake_shared_list)

def get_id():
    """ Get uniq ID depending on process type. """
    #global pid
    #global proc_thread_id
    #if proc_thread_id:
    #    return proc_thread_id
    proc_name = get_proc_name()
    thread_id = get_thread_id()
    proc_thread_id = "%s (%s:%s)" % (proc_name, os.getpid(), thread_id)
    return proc_thread_id

def get_proc_type():
    """ Get process type. """
    proc_type = "thread"
    is_main_thread = isinstance(threading.current_thread(), threading._MainThread)
    if is_main_thread:
        proc_type = "process"
    return proc_type

def get_proc_name():
    """ Get process name. """
    proc = psutil.Process(os.getpid())
    # WORKAROUND: name method changed between psutil versions.
    try:
        proc_name = proc.name()
    except:
        proc_name = proc.name
    return proc_name

def get_thread_id():
    """ Get current thread ID as string. """
    thread_id = str(threading.currentThread().ident)
    return thread_id

def get_thread_name():
    """ Get current thread name. """
    thread_name = threading.currentThread().getName()
    return thread_name

def signal_handler(_signal, frame):
    """ Handle SIGTERM. """
    from otpme.lib import config
    if _signal != 15:
        return
    # Get logger.
    logger = config.logger
    msg = "Received SIGTERM."
    logger.info(msg)
    os._exit(0)

def atfork(keep_locks=False, quiet=True,
    exit_on_signal=False, signal_method=None):
    """ Do multiprocessing stuff. """
    from otpme.lib import log
    from otpme.lib import config
    from otpme.lib import backend
    from otpme.lib import locking
    from otpme.lib import connections
    global pid
    #global proc_thread_id
    global message_queues
    global posix_semaphores
    #proc_thread_id = None
    pid = os.getpid()
    proc_type = get_proc_type()
    if proc_type != "process":
        msg = "Cannot run this method from within a thread."
        raise OTPmeException(msg)
    # Make sure we use new DB connections.
    backend.atfork()
    _index = config.get_index_module()
    _index.atfork()
    # Set signal handler to handle process exit on signal.
    if exit_on_signal:
        if signal_method is None:
            signal_method = signal_handler
        signal.signal(signal.SIGTERM, signal_method)
        signal.signal(signal.SIGINT, signal_method)
    # Clear log locks etc.
    log.atfork()
    # Get logger.
    logger = config.logger
    if config.debug_level() > 3:
        msg = "Process forked: %s" % pid
        logger.debug(msg)
    # Make sure we do not handle locks of parent process.
    if not keep_locks:
        locking.atfork()
    # Make sure we do not use connections of parent process.
    connections.atfork()
    # Clear messages queues from parent process.
    message_queues = []
    # Clear semaphores from parent process.
    posix_semaphores.clear()

def cleanup(keep_queues=False):
    """ Do a clean process exit. """
    from otpme.lib import config
    from otpme.lib import backend
    from otpme.lib import locking
    from otpme.lib import connections
    global message_queues
    global posix_semaphores
    proc_type = get_proc_type()
    if proc_type != "process":
        msg = "Cannot run this method from within a thread."
        raise OTPmeException(msg)
    # Get logger.
    logger = config.logger
    # Get ID.
    pid = os.getpid()
    _index = config.get_index_module()
    _index.cleanup()
    try:
        connections.cleanup()
    except Exception as e:
        msg = "Connection cleanup failed: %s: %s" % (pid, e)
        logger.critical(msg)
    try:
        locking.cleanup()
    except Exception as e:
        msg = "Lock cleanup failed: %s: %s" % (pid, e)
        logger.critical(msg)
    try:
        backend.cleanup()
    except Exception as e:
        msg = "Backend cleanup failed: %s: %s" % (pid, e)
        logger.critical(msg)
        config.raise_exception()
    for x in cluster_read_locks:
        x_lock = cluster_read_locks[x]
        x_lock.release_lock(force=True)
    for x in cluster_write_locks:
        x_lock = cluster_write_locks[x]
        x_lock.release_lock(force=True)
    if not keep_queues:
        for x in list(message_queues):
            try:
                x.close()
            except posix_ipc.PermissionsError:
                pass
            except posix_ipc.ExistentialError:
                pass
            try:
                x.unlink()
            except posix_ipc.ExistentialError:
                pass
            except posix_ipc.PermissionsError:
                pass
            message_queues.remove(x)
    for sem_name in dict(posix_semaphores):
        sem = posix_semaphores[sem_name]
        try:
            sem.close()
        except posix_ipc.ExistentialError:
            pass
        except posix_ipc.PermissionsError:
            pass
        try:
            sem.unlink()
        except posix_ipc.ExistentialError:
            pass
        except posix_ipc.PermissionsError:
            pass
        posix_semaphores.pop(sem_name)

def get_bool(name, default=False, random_name=True, init=True):
    class SharedBool(object):
        def __init__(self, name, default=False, random_name=True, init=True):
            self.size = 1
            if random_name:
                random_string = stuff.gen_secret(32)
                name = "%s-%s" % (name, random_string)
            self.name = name
            self.default_value = default
            if init:
                self.init()
        def init(self):
            shmem_name = "/%s" % self.name
            self.shmem = posix_ipc.SharedMemory(shmem_name,
                                            posix_ipc.O_CREAT,
                                            size=self.size)
            self._value = mmap.mmap(self.shmem.fd, self.size)
            self.value = self.default_value
        @property
        def value(self):
            if self._value[0] == 0:
                return False
            return True
        @value.setter
        def value(self, new_val):
            try:
                self._value[0] = new_val
            except ValueError:
                pass
        def close(self):
            self._value.close()
            self.shmem.close_fd()
            try:
                self.shmem.unlink()
            except posix_ipc.ExistentialError:
                pass
    shared_bool = SharedBool(name=name,
                        default=default,
                        random_name=random_name,
                        init=init)
    return shared_bool

def get_shm_string(name, size=1024, value=None):
    class SharedString(object):
        def __init__(self, name, size=1024, value=None):
            self.name = name
            shmem_name = "/%s" % self.name
            self.shmem = posix_ipc.SharedMemory(shmem_name,
                                            posix_ipc.O_CREAT,
                                            size=size)
            self._value = mmap.mmap(self.shmem.fd, size)
            if value is not None:
                self.value = value
        @property
        def value(self):
            null_byte_index = self._value.find(b'\0')
            value = self._value[:null_byte_index]
            value = value.decode()
            return value
        @value.setter
        def value(self, new_val):
            new_val_len = len(new_val)
            new_val = new_val.encode()
            self._value[:new_val_len+1] = new_val + b'\0'
        def close(self):
            self._value.close()
            self.shmem.close_fd()
        def unlink(self):
            try:
                self.shmem.unlink()
            except posix_ipc.ExistentialError:
                pass
    shared_string = SharedString(name, value=value, size=size)
    return shared_string

def get_dict(name=None, clear=False, **kwargs):
    from otpme.lib import config
    global manager
    if manager is not None:
        return manager.dict()
    if name is None:
        name = stuff.gen_uuid()
    _cache = config.get_cache_module()
    pool = _cache.get_pool()
    shared_dict = _cache.get_dict(name, pool=pool, clear=clear, **kwargs)
    return shared_dict

def get_list(name=None, clear=False, **kwargs):
    from otpme.lib import config
    global manager
    if manager is not None:
        return manager.list()
    if name is None:
        name = stuff.gen_uuid()
    _cache = config.get_cache_module()
    pool = _cache.get_pool()
    shared_list = _cache.get_list(name, pool=pool, clear=clear, **kwargs)
    return shared_list

def create_shared_objects():
    """ Set shared objects. """
    from otpme.lib import config
    global shared_objects
    _cache = config.get_cache_module()
    pool = _cache.get_pool()
    for o_name in shared_objects:
        o_type = shared_objects[o_name]['type']
        o_clear = shared_objects[o_name]['clear']
        o_locking = shared_objects[o_name]['locking']
        o_pickle = shared_objects[o_name]['pickle']
        # Get module.
        module = sys.modules[MODULE_PATH]
        current_o = getattr(module, o_name)
        if o_type == "dict":
            try:
                shared_o = _cache.get_dict(name=o_name,
                                        pool=pool,
                                        clear=o_clear,
                                        locking=o_locking,
                                        pickle=o_pickle)
            except Exception as e:
                msg = ("Failed to get shared dict: %s: %s" % (o_name, e))
                print(msg)
                raise
            for key in current_o:
                val = current_o[key]
                shared_o[key] = val
        elif o_type == "list":
            try:
                shared_o = _cache.get_list(name=o_name,
                                        pool=pool,
                                        clear=o_clear,
                                        locking=o_locking,
                                        pickle=o_pickle)
            except Exception as e:
                msg = ("Failed to get shared dict: %s: %s" % (o_name, e))
                print(msg)
                raise
            for x in current_o:
                shared_o.append(x)
        setattr(module, o_name, shared_o)

def mgr_init():
    """ Make multiprocessing manager ignore signals """
    # http://jtushman.github.io/blog/2014/01/14/python-|-multiprocessing-and-interrupts/
    signal.signal(signal.SIGINT, signal.SIG_IGN)

def drop_privileges(user=None, group=None, groups=None):
    """ Drop privileges. """
    from otpme.lib import config
    # Get logger.
    logger = config.logger
    # Check if we are already the given user/group.
    if user == config.system_user():
        user = None
    if group == config.system_group():
        group = None
    # Remove group privileges.
    if user or group:
        os.setgroups([])

    group_ids = []
    # Get group IDs.
    if groups:
        for g in groups:
            try:
                x = grp.getgrnam(g).gr_gid
            except Exception as e:
                msg = "Failed to resolve group: %s" % g
                raise OTPmeException(msg)
            group_ids.append(x)
        os.setgroups(group_ids)

    # Drop group privileges.
    if group:
        try:
            gid = grp.getgrnam(group).gr_gid
            os.setgid(gid)
        except Exception as e:
            msg = "Failed to drop privileges (group)"
            raise OTPmeException(msg)
        if config.debug_level() > 3:
            logger.debug("Changed group to: %s" % group)

    # Drop user privileges.
    if user:
        try:
            uid = pwd.getpwnam(user).pw_uid
            os.setuid(uid)
        except Exception as e:
            msg = "Failed to drop privileges (group)"
            raise OTPmeException(msg)
        if config.debug_level() > 3:
            logger.debug("Changed user to: %s" % user)
        # Change to users home directory to prevent any chdir() problems.
        user_home_dir = os.path.expanduser("~%s" % user)
        if os.path.exists(user_home_dir):
            try:
                os.chdir(user_home_dir)
            except Exception as e:
                msg = "Failed to change cwd: %s" % e
                raise OTPmeException(msg)

def start_process(name, target, target_args=None,
    target_kwargs=None, daemon=False,
    join=False, start=True):
    """ Start new process. """
    proc_kwargs = {}
    if target_args:
        proc_kwargs['args'] = target_args
    if target_kwargs:
        proc_kwargs['kwargs'] = target_kwargs

    new_proc = multiprocessing.Process(name=name,
                                    target=target,
                                    **proc_kwargs)
    if daemon:
        new_proc.daemon = daemon
    if start:
        # Start process.
        new_proc.start()
        # Start daemon thread to join process on exit.
        if join:
            start_thread(name=name, target=new_proc.join, daemon=True)
    return new_proc

def start_thread(name, target, target_args=None,
    target_kwargs=None, daemon=False, start=True):
    """ Start new process. """
    thread_kwargs = {}
    if target_args:
        thread_kwargs['args'] = target_args
    if target_kwargs:
        thread_kwargs['kwargs'] = target_kwargs

    new_thread = threading.Thread(name=name, target=target, **thread_kwargs)
    if daemon:
        new_thread.setDaemon(True)
    if start:
        new_thread.start()
    return new_thread

class OTPmeSyncManager(SyncManager):
    """ Wrapper class to change user and set proctitle. """
    def __init__(self, *args, **kwargs):
        try:
            OTPmeSyncManager._otpme_proc_title = kwargs.pop('_otpme_proc_title')
        except:
            OTPmeSyncManager._otpme_user = None
        try:
            OTPmeSyncManager._otpme_user = kwargs.pop('_otpme_user')
        except:
            OTPmeSyncManager._otpme_user = None
        try:
            OTPmeSyncManager._otpme_group = kwargs.pop('_otpme_group')
        except:
            OTPmeSyncManager._otpme_group = None
        super(OTPmeSyncManager, self).__init__(*args, **kwargs)

    @classmethod
    def _run_server(cls, *args, **kwargs):
        from otpme.lib import config
        pid = os.getpid()
        msg = "Starting multiprocessing manager: %s" % pid
        logger = config.logger
        logger.debug(msg)
        # Set process title..
        if cls._otpme_proc_title:
            setproctitle.setproctitle(cls._otpme_proc_title)
        # Drop privileges.
        drop_privileges(cls._otpme_user, cls._otpme_group)
        super(OTPmeSyncManager, cls)._run_server(*args, **kwargs)

def get_sync_manager(name, proc_title=None, user=None, group=None):
    """
    Make sure multiprocessing.SyncManager() uses
    a proper socket directory.
    """
    from otpme.lib import config
    if not proc_title:
        proc_title = "multiprocessing manager"
        if name:
            proc_title = "%s (%s)" % (name, proc_title)
    # Gen uniq socket path.
    socket_id = stuff.gen_secret(len=32)
    socket_dir = config.sockets_dir + "/manager"
    socket_path = socket_dir + "/" + name + "-" + socket_id
    if not os.path.exists(socket_dir):
        filetools.create_dir(path=socket_dir,
                            user=user,
                            group=group,
                            mode=0o1777)
    socket_path = socket_path.replace(" ", "_")
    # Create manager instance.
    sync_manager = OTPmeSyncManager(address=socket_path,
                                    _otpme_proc_title=proc_title,
                                    _otpme_user=user,
                                    _otpme_group=group)
    sync_manager.start(mgr_init)
    # Set socket permissions.
    filetools.set_fs_permissions(path=socket_path,
                                mode=0o600,
                                recursive=False)
    if user or group:
        # Set socket directory ownership.
        filetools.set_fs_ownership(path=socket_path,
                                    user=user,
                                    group=group,
                                    recursive=False)
    return sync_manager


class Event(object):
    def __init__(self, event_name=None):
        if event_name is None:
            event_name = "/%s" % stuff.gen_uuid()
        self.name = event_name
        self._semaphore = None

    def __str__(self):
        return self.name

    def open_semaphore(self):
        global posix_semaphores
        semaphore = posix_ipc.Semaphore(name=self.name,
                                        flags=posix_ipc.O_CREAT,
                                        mode=0o660)
        sem_path = f"/dev/shm/sem.{self.name.lstrip('/')}"
        uid = pwd.getpwnam(config.user).pw_uid
        gid = grp.getgrnam(config.group).gr_gid
        try:
            os.chown(sem_path, uid, gid)
        except FileNotFoundError:
            pass
        if semaphore.name not in posix_semaphores:
            posix_semaphores[semaphore.name] = semaphore
        return semaphore

    def open(self):
        self._semaphore = self.open_semaphore()

    def wait(self, timeout=None):
        if not self._semaphore:
            self.open()
        try:
            self._semaphore.acquire(timeout=timeout)
        except posix_ipc.BusyError:
            raise TimeoutReached()
        except posix_ipc.SignalError:
            pass
        self.close()

    def set(self):
        if not self._semaphore:
            self.open()
        self._semaphore.release()
        self.close()

    def close(self):
        if self._semaphore is None:
            return
        self._semaphore.close()
        self._semaphore = None

    def unlink(self):
        global posix_semaphores
        if self._semaphore is None:
            self.open()
        try:
            self._semaphore.unlink()
        except posix_ipc.ExistentialError:
            pass
        except posix_ipc.PermissionsError:
            pass
        try:
            self._semaphore.close()
        except posix_ipc.ExistentialError:
            pass
        except posix_ipc.PermissionsError:
            pass
        try:
            posix_semaphores.pop(self._semaphore.name)
        except KeyError:
            pass
        self._semaphore = None

class MessageQueue(object):
    def __init__(self, name, identifier=None, max_message_size=None):
        from otpme.lib import config
        if identifier is None:
            identifier = stuff.gen_uuid()
        self.identifier = identifier
        self._queue = None
        self.queue_name = "/otpme-ipc-%s" % name
        if self.identifier:
            self.queue_name = "/otpme-ipc-%s-%s" % (self.identifier, name)
        self.logger = config.logger
        if max_message_size is None:
            max_message_size = config.posix_msgsize_max
        self.max_message_size = max_message_size

    @property
    def queue(self):
        if self._queue is None:
            try:
                queue = posix_ipc.MessageQueue(self.queue_name,
                                            flags=posix_ipc.O_CREAT,
                                            max_message_size=self.max_message_size)
            except posix_ipc.PermissionsError as e:
                msg = ("Failed to open posix message queue: %s: %s"
                        % (self.queue_name, e))
                self.logger.critical(msg)
                raise
            except OSError as e:
                msg = ("Failed to open posix message queue: %s: %s"
                        % (self.queue_name, e))
                self.logger.critical(msg)
                raise
            self._queue = queue
        return self._queue

    def send(self, message, timeout=None):
        from otpme.lib import locking
        lock = locking.acquire_lock(lock_type=LOCK_TYPE,
                                    lock_id=self.queue_name)
        try:
            # Encode message.
            data = json.dumps(message)
            # Get length of data to send.
            data_len = len(data)
            # Send length of data to peer.
            request = "req_len:" + str(data_len)
            self.raw_send(request, timeout=timeout)
            # If data fits into one message send it.
            if data_len <= self.max_message_size:
                self.raw_send(data, timeout=timeout)
                return
            # Send data in chunks.
            for i in range(0, data_len, self.max_message_size):
                chunk = data[i:i + self.max_message_size]
                self.raw_send(chunk, timeout=timeout)
        finally:
            lock.release_lock()

    def recv(self, timeout=None):
        """ Function to handle data receiving through socket connection. """
        # Get data from peer.
        data = self.raw_recv(timeout=timeout)
        # Handle timeout.
        if data is None:
            if timeout is not None:
                msg = "Queue timeout reached: %s" % self.queue
                raise TimeoutReached(msg)
        # Try to get data length from peer.
        try:
            data_len = int(data.split(":")[1])
        except:
            response = (_("Error: Unable to get data len from queue request: %s")
                        % data)
            raise OTPmeException(response)
        # If data fits in to one message receive it.
        if data_len <= self.max_message_size:
            received = self.raw_recv(timeout=timeout)
            if received is None:
                return
        else:
            # Receive data that does not fit into one message in chunks.
            chunks = []
            bytes_recvd = 0
            while bytes_recvd < data_len:
                chunk = self.raw_recv(timeout=timeout)
                if chunk is None:
                    return
                if chunk == '':
                    msg = ("Broken connection while receiving data.")
                    raise OTPmeException(msg)
                chunks.append(chunk)
                bytes_recvd = bytes_recvd + len(chunk)
            # Join chunks.
            received = ''.join(chunks)
        # Decode received data.
        if len(received) > 0:
            try:
                message = json.loads(received)
            except Exception as e:
                msg = "Failed to decode received data: %s" % e
                raise OTPmeException(msg)
        return message

    def raw_send(self, data, timeout=None):
        try:
            self.queue.send(data, timeout=timeout)
        except posix_ipc.BusyError:
            pass
        except posix_ipc.ExistentialError:
            msg = "Queue closed."
            raise QueueClosed(msg)
        except posix_ipc.SignalError:
            msg = "Exiting on signal."
            raise ExitOnSignal(msg)

    def raw_recv(self, timeout=None):
        try:
            (data, prio) = self.queue.receive(timeout=timeout)
        except posix_ipc.BusyError:
            data = None
        except posix_ipc.ExistentialError:
            msg = "Queue closed."
            raise QueueClosed(msg)
        except posix_ipc.SignalError:
            msg = "Exiting on signal."
            raise ExitOnSignal(msg)
        if data is not None:
            data = data.decode()
        return data

    def close(self):
        if self._queue is None:
            return
        try:
            self._queue.close()
        except posix_ipc.ExistentialError:
            pass

    def unlink(self):
        global message_queues
        if self._queue is None:
            return
        try:
            self._queue.unlink()
        except posix_ipc.ExistentialError:
            pass
        try:
            message_queues.remove(self._queue)
        except:
            pass

class InterProcessQueue(object):
    """ Manage interprocess communication. """
    def __init__(self, identifier=None):
        self.queues = {}
        self.message_queue = {}
        self.identifier = identifier
        if identifier is None:
            self.identifier = stuff.gen_uuid()

    def get_handler(self, name=None):
        """ Get communication handler. """
        if name is None:
            name = stuff.gen_uuid()
        class CommunicationHandler(object):
            def __init__(own, name):
                own.name = name
            def send(own, recipient, command, **kwargs):
                return self.send(own.name, recipient, command, **kwargs)
            def recv(own, timeout=None, **kwargs):
                return self.recv(own.name, timeout=timeout, **kwargs)
            def get_child(own, name=None):
                if name is None:
                    name = stuff.gen_uuid()
                return self.get_handler(name)
            def close(own):
                queue = self.get_queue(own.name, pop=False)
                if queue is None:
                    return
                try:
                    queue.close()
                except posix_ipc.PermissionsError:
                    pass
            def unlink(own):
                queue = self.get_queue(own.name, pop=True)
                if queue is None:
                    return
                try:
                    queue.unlink()
                except posix_ipc.PermissionsError:
                    pass
            def info(own):
                queue = self.get_queue(own.name)
                print(queue.queue_name)
        self.get_queue(name, autoclean=False)
        comm_handler = CommunicationHandler(name)
        return comm_handler

    def get_queue(self, name, pop=False, autoclean=True):
        """ Get queue for the given member. """
        global message_queues
        if pop:
            try:
                queue = self.queues[name].pop("queue")
            except:
                queue = MessageQueue(name, identifier=self.identifier)
            return queue
        try:
            queue = self.queues[name]['queue']
        except:
            self.queues[name] = {}
            queue = MessageQueue(name, identifier=self.identifier)
            self.queues[name]['queue'] = queue
        if autoclean:
            if queue not in message_queues:
                message_queues.append(queue)
        return queue

    def build_message(self, sender, command, data=None):
        message = {
                'sender'    : sender,
                'command'   : command,
                'data'      : data,
                }
        return message

    def decode_message(self, message):
        # Get sender.
        try:
            sender = message['sender']
        except:
            msg = "Receive invalid message: Sender missing"
            raise OTPmeException(msg)
        # Get command.
        try:
            command = message['command']
        except:
            msg = "Receive invalid message: Command missing"
            raise OTPmeException(msg)
        # Get data.
        try:
            data = message['data']
            message = message['command']
        except:
            pass
        return sender, command, data

    def queue_message(self, recipient, sender, command, data=None):
        """ Queue messages. """
        try:
            recipient_queue = self.message_queue[recipient]
        except:
            recipient_queue = {}
        try:
            sender_messages = recipient_queue[sender]
        except:
            sender_messages = []
        sender_messages.append((sender, command, data))
        recipient_queue[sender] = sender_messages
        self.message_queue[recipient] = recipient_queue

    def get_queued_message(self, recipient, sender=None):
        """ Get queued message. """
        try:
            recipient_queue = self.message_queue[recipient]
        except:
            return
        if sender is None:
             sender = list(recipient_queue)[0]
        try:
            sender_messages = recipient_queue[sender]
        except:
            return
        try:
            sender, command, data = sender_messages.pop()
            if not sender_messages:
                recipient_queue.pop(sender)
        except:
            return
        recipient_queue[sender] = sender_messages
        self.message_queue[recipient] = recipient_queue
        return sender, command, data

    def send(self, sender, recipient, command,
        data=None, timeout=None, autoclose=False):
        """ Send message. """
        # Build message.
        message = self.build_message(sender=sender, command=command, data=data)
        # Get queue.
        try:
            queue = self.get_queue(recipient, pop=autoclose, autoclean=False)
        except:
            msg = "Unknown recipient: %s" % recipient
            raise OTPmeException(msg)
        # Send message.
        try:
            queue.send(message, timeout=timeout)
        except ExitOnSignal:
            pass
        finally:
            if autoclose:
                queue.close()

    def recv(self, recipient, sender=None, timeout=None):
        """ Receive message. """
        # Try to get queued message.
        try:
            sender, command, data = self.get_queued_message(recipient, sender)
            return sender, command, data
        except:
            pass
        while True:
            # Get queue.
            queue = self.get_queue(recipient)
            # Try to get message from queue.
            message = queue.recv(timeout=timeout)
            # Decode message.
            try:
                _sender, command, data = self.decode_message(message)
            except Exception as e:
                msg = "Failed to decode message: %s" % e
                raise OTPmeException(msg)
            # Check if message is from requested sender.
            sender_ok = False
            if sender is None:
                sender_ok = True
            if _sender == sender:
                sender_ok = True
            if sender_ok:
                return _sender, command, data
            # Queue message from other sender than requested.
            self.queue_message(recipient, _sender, command, data)

    def close(self):
        for x in self.queues:
            try:
                queue = self.queues[x]['queue']
            except:
                continue
            try:
                queue.close()
            except posix_ipc.PermissionsError:
                pass

    def unlink(self):
        for x in self.queues:
            try:
                queue = self.queues[x]['queue']
            except:
                continue
            try:
                queue.unlink()
            except posix_ipc.PermissionsError:
                pass

class SharedDict(dict):
    """ A simple shared dict class to be used by e.g. redis. """
    def __init__(self, name):
        self.name = name
        # Data store for fake shared dicts.
        self._dict = {}
        self.dict_data_key = "dict_data"
        self.dict_expire_key = "dict_key_expire"

    def get_key_id(self, key):
        key = "%s.%s.%s" % (self.name, self.dict_data_key, key)
        return key

    def get_key_expire_id(self, key):
        expire_key = "%s.%s.%s" % (self.name, self.dict_expire_key, key)
        return expire_key

    def __setitem__(self, key, item):
        self.add(key, item)

    def __getitem__(self, key):
        return self.get(key)

    def __len__(self):
        x = self.dict()
        return len(x)

    def __delitem__(self, key):
        self.delete(key)

    def copy(self):
        x = self.dict()
        dict_copy = x.copy()
        if dict_copy is None:
            dict_copy = {}
        return dict_copy

    def has_key(self, k):
        keys = list(self)
        return k in keys

    #def update(self, *args, **kwargs):
    #    return self._dict.update(*args, **kwargs)

    def dict(self):
        items = self.items()
        _dict = {}
        for x in items:
            key = x[0]
            value = x[1]
            _dict[key] = value
        return _dict

    def pop(self, *args):
        return self.delete(*args)

    def __contains__(self, key):
        # Using self.get() instead of self.keys() is faster!
        try:
            self.get(key)
        except KeyError:
            return False
        return True

    def __iter__(self):
        x = self.dict()
        return iter(x)

    def __str__(self):
        x = self.dict()
        return x.__str__()

    def keys(self):
        keys = self._dict.keys()
        return keys

    def add(self, key, value, **kwargs):
        self._dict[key] = value

    def get(self, key):
        value = self._dict[key]
        return value

    def delete(self, key):
        value = self._dict.pop(key)
        return value

class SharedList(list):
    """ A simple shared list class to be used by e.g. redis. """
    def __init__(self, name):
        self.name = name
        # Data store for fake shared lists.
        self._list = []

    #def __setitem__(self, i, val):
    #    self.insert(i, val)

    def __getitem__(self, i):
        val = self.list[i]
        return val

    #def __repr__(self):
    #   x = self.list
    #    return repr(x)

    def __len__(self):
        x = self.list
        return len(x)

    #def __delitem__(self, i):
    #    self.remove(i)

    def pop(self, *args):
        return self.delete(*args)

    def __contains__(self, val):
        return val in self.list

    def __iter__(self):
        x = self.list
        return iter(x)

    def __str__(self):
        x = self.list
        return x.__str__()

    @property
    def list(self):
        return self._list

    @list.setter
    def list(self, _list):
        self._list = _list

    def clear(self):
        self._list = []

    def insert(self, i, value):
        _list = self.list
        _list.insert(i, value)
        self.list = _list

    def append(self, value):
        _list = self.list
        _list.insert(len(self.list), value)
        self.list = _list

    def remove(self, value):
        _list = self.list
        _list.remove(value)
        self.list = _list
