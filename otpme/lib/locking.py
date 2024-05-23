# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time
import atexit
#import datetime
from functools import wraps
#from functools import update_wrapper
#import multiprocessing as _multiprocessing

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import multiprocessing
from otpme.lib.filetools import AtomicFileLock

from otpme.lib.exceptions import *

current_thread_fds = {}
current_thread_locks = {}

registered_lock_types = {
                        'node_sync'             : 'config',
                        'sync_status'           : 'config',
                        'data_revision_update'  : 'config',
                        }

def atfork():
    """ Make sure we do not handle locks from parent process. """
    global current_thread_locks
    global current_thread_fds
    current_thread_fds.clear()
    current_thread_locks.clear()

def register_lock_type(lock_type, module):
    """ Register lock type. """
    global registered_lock_types
    try:
        x_module = registered_lock_types[lock_type]
    except:
        x_module = None
    if x_module and x_module != module:
        msg = "Lock type already registered: %s" % lock_type
        raise AlreadyExists(msg)
    registered_lock_types[lock_type] = module

#def oid_lock(kwargs_oid_args=["object_id"],
#    oid_args_fallback=True, args_oid_pos=None, write=False):
#    """ Decorator to handle OID locking. """
#    def wrapper(func):
#        @wraps(func)
#        def wrapped(*args, **kwargs):
#            lock_oids = []
#            func_name = func.__name__
#            # Get no lock argument.
#            try:
#                no_lock = kwargs['no_lock']
#            except:
#                no_lock = False
#
#            if not config.oid_locking_enabled:
#                no_lock = True
#
#            if no_lock:
#                # Run original function.
#                result = func(*args, **kwargs)
#                return result
#
#            # Try to get OID from kwargs.
#            oid_found = False
#            if kwargs_oid_args:
#                for x in kwargs_oid_args:
#                    try:
#                        lock_oid = kwargs[x]
#                    except:
#                        continue
#                    lock_oids.append(lock_oid)
#                    oid_found = True
#
#            if not oid_found and not oid_args_fallback:
#                msg = ("Unable to get OID from kwargs: %s: %s"
#                    % (func_name, ",".join(kwargs_oid_arg)))
#                raise OTPmeException(msg)
#
#            if not oid_found and not args_oid_pos:
#                msg = ("Unable to get OID. Got no args_oid_pos argument: %s"
#                        % func_name)
#                raise OTPmeException(msg)
#
#            # Fallback to args.
#            if not oid_found:
#                for x in args_oid_pos:
#                    try:
#                        lock_oid = args[x]
#                    except:
#                        continue
#                    lock_oids.append(lock_oid)
#                    oid_found = True
#
#            if not oid_found:
#                oid_pos_str = [str(x) for x in args_oid_pos]
#                msg = ("Unable to get OID from args: %s: %s"
#                    % (func_name, ",".join(oid_pos_str)))
#                raise OTPmeException(msg)
#
#            if not lock_oids:
#                msg = "Unable to lock object: No object ID found"
#                raise OTPmeException(msg)
#
#            # List with all locks we added.
#            locks = []
#            lock_caller = func_name
#            for x in lock_oids:
#                lock_id = x.read_oid
#                try:
#                    lock = acquire_lock(lock_type="oid",
#                                        lock_id=lock_id,
#                                        lock_caller=lock_caller,
#                                        write=write)
#                    # Remember locks we acquired.
#                    locks.append(lock)
#                except Exception as e:
#                    config.raise_exception()
#                    msg = "Failed to acquire backend lock: %s: %s" % (lock_id, e)
#                    config.logger.critical(msg, exc_info=True)
#                    continue
#
#            # Run original function.
#            try:
#                result = func(*args, **kwargs)
#            finally:
#                # Release locks we acquired.
#                for x in locks:
#                    x.release_lock(lock_caller=lock_caller)
#            return result
#
#        # Update func/method.
#        update_wrapper(wrapped, func)
#        if not hasattr(wrapped, '__wrapped__'):
#            # Python 2.7
#            wrapped.__wrapped__ = func
#        return wrapped
#
#    return wrapper

def object_lock(write=True, recursive=False, timeout=None,
    reload_on_change=True, full_lock=False):
    """ Decorator to handle object lock. """
    def wrapper(f):
        @wraps(f)
        def wrapped(self, *f_args, **f_kwargs):
            lock_caller = f.__name__
            try:
                callback = f_kwargs['callback']
            except:
                callback = None
            # Check if locking was disabled by lock_object kwarg.
            try:
                lock_object = f_kwargs.pop('lock_object')
            except:
                lock_object = None
            # Check if lock clustering was disabled.
            try:
                cluster_lock = f_kwargs.pop('cluster_lock')
            except:
                cluster_lock = True
            # Wait timeout for the object lock.
            try:
                lock_wait_timeout = f_kwargs.pop('lock_wait_timeout')
            except:
                lock_wait_timeout = timeout
            # Reload object if it was changed while waiting for the lock.
            try:
                lock_reload_on_change = f_kwargs.pop('reload_on_change')
            except:
                lock_reload_on_change = reload_on_change

            if full_lock:
                self.full_write_lock = True

            # Acquire lock
            if lock_object is None:
                lock_object = True

            if lock_object:
                lock_failed_msg = "Failed to acquire lock"
                try:
                    self.acquire_lock(lock_caller,
                                    write=write,
                                    cluster=cluster_lock,
                                    timeout=lock_wait_timeout,
                                    reload_on_change=lock_reload_on_change,
                                    recursive=recursive,
                                    callback=callback)
                except LockWaitTimeout as e:
                    if callback:
                        msg = "%s: %s" % (lock_failed_msg, e)
                        return callback.error(msg)
                    raise
                except LockWaitAbort as e:
                    if callback:
                        msg = "%s: %s" % (lock_failed_msg, e)
                        return callback.error(msg)
                    raise
                except UnknownObject as e:
                    if callback:
                        msg = "%s: %s" % (lock_failed_msg, e)
                        return callback.error(msg)
                    raise

            # Call given class method.
            try:
                result = f(self, *f_args, **f_kwargs)
            finally:
                # Make sure we release lock.
                if lock_object:
                    self.release_lock(lock_caller,
                                    recursive=recursive,
                                    callback=callback)
            return result
        # Mark the target method as being locked by us. This is used in
        # OTPmeJob() to decide when to pass lock_wait_timeout to us.
        wrapped.object_lock = True
        return wrapped
    return wrapper

def remember_fd(fd):
    global current_thread_fds
    thread_id = multiprocessing.get_thread_id()
    if thread_id not in current_thread_fds:
        current_thread_fds[thread_id] = {}
    current_thread_fds[thread_id][fd] = fd

def forget_fd(fd):
    global current_thread_fds
    thread_id = multiprocessing.get_thread_id()
    try:
        current_thread_fds[thread_id].pop(fd)
    except:
        pass

def get_lock_id(lock_type, lock_id):
    """ Add lock type to lock ID. """
    lock_id = "%s:%s" % (lock_type, lock_id)
    return lock_id

def get_lock(lock_type, lock_id):
    global current_thread_locks
    lock_id = get_lock_id(lock_type, lock_id)
    thread_id = multiprocessing.get_thread_id()
    f_lock = current_thread_locks[thread_id][lock_id]
    return f_lock

def remember_lock(lock):
    global current_thread_locks
    thread_id = multiprocessing.get_thread_id()
    if thread_id not in current_thread_locks:
        current_thread_locks[thread_id] = {}
    current_thread_locks[thread_id][lock.lock_id] = lock

def forget_lock(lock_id):
    global current_thread_locks
    thread_id = multiprocessing.get_thread_id()
    try:
        current_thread_locks[thread_id].pop(lock_id)
    except:
        pass

def acquire_lock(lock_type, lock_id, write=True, timeout=None,
    lock_caller=None, cluster=False, callback=None):
    """ Get lock object. """
    from otpme.lib import config
    global registered_lock_types
    if lock_type not in registered_lock_types:
        msg = "Lock type not registered: %s" % lock_type
        raise OTPmeException(msg)
    # Try to get lock from cache.
    try:
        _lock = get_lock(lock_type, lock_id)
    except KeyError:
        # Add new lock.
        try:
            if config.locking_enabled:
                _lock = OTPmeLock(lock_type=lock_type,
                                    lock_id=lock_id,
                                    write=write,
                                    cluster=cluster,
                                    callback=callback)
            else:
                _lock = OTPmeFakeLock(lock_type=lock_type, lock_id=lock_id)
        except Exception as e:
            config.raise_exception()
            msg = "Failed to get lock: %s" % e
            raise OTPmeException(msg)
        # Add lock to cache.
        remember_lock(_lock)

    # Acquire lock.
    _lock.acquire_lock(lock_caller=lock_caller,
                        timeout=timeout)
    return _lock

def cleanup_fds():
    """ Make sure to remove all file locks on exit. """
    global current_thread_fds
    thread_id = multiprocessing.get_thread_id()
    try:
        lock_list = dict(current_thread_fds[thread_id])
    except:
        return
    for x in lock_list:
        fd = lock_list[x]
        try:
            fd.close()
        except:
            pass
        # FIXME: Removing files with os.remove here will lead to deadlocks.
        #        We need to do it atomic to prevent us from deleting a file
        #        that is used by an other process as lock.
        #try:
        #    os.remove(fd.path)
        #except:
        #    pass

def cleanup():
    """ Cleanup on process exit. """
    from otpme.lib import config
    try:
        if config.debug_level("locking") > 1:
            # Get logger.
            logger = config.logger
            msg = "Doing process exit cleanup."
            logger.debug(msg)
    except:
        pass
    cleanup_fds()

# Release locks on exit.
atexit.register(cleanup)

class OTPmeFakeLock(object):
    """ Simple fake locking class. """
    def __init__(self, lock_type, lock_id, write=False):
        """ Init class variables. """
        self._lock_id = lock_id
        self.lock_id = get_lock_id(lock_type, lock_id)
        self.lock_type = lock_type
        self.write = write
        self.outdated = False
        self.lock_callers = []

    def __repr__(self):
        # We need a string when object is used as dict key!
        return self.__str__()

    def __hash__(self):
        return hash(self.__str__())

    def __str__(self):
        return self.lock_id

    def acquire_lock(self, lock_caller=None, skip_same_caller=False, **kwargs):
        """ Acquire lock. """
        # Set default lock caller.
        if lock_caller is None:
            lock_caller = self.lock_id
        # Add caller.
        add_lock_caller = True
        if skip_same_caller:
            if lock_caller in self.lock_callers:
                add_lock_caller = False
        if add_lock_caller:
            self.lock_callers.append(lock_caller)

    def release_lock(self, lock_caller=None, _forget_lock=True, **kwargs):
        """ Release lock caller. """
        # Set default lock caller.
        if lock_caller is None:
            lock_caller = self.lock_id
        # Remove lock caller from list.
        try:
            self.lock_callers.remove(lock_caller)
        except:
            msg = ("Got lock release request from unknown caller: %s: %s"
                    % (self.lock_id, lock_caller))
            raise OTPmeException(msg)
        if self.lock_callers:
            return
        if not _forget_lock:
            return
        # We dont want the released lock to be re-used.
        self.forget_lock()

    def forget_lock(self):
        forget_lock(self.lock_id)

    def is_locked(self):
        """ Check if the lock is acquired. """
        if self.lock_callers:
            return True
        return False

class OTPmeLock(OTPmeFakeLock):
    """ Simple locking class. """
    def __init__(self, lock_type, lock_id, write=False,
        cluster=False, callback=None):
        """ Init class variables. """
        from otpme.lib import config
        from otpme.lib.oid import oid_to_fs_name
        # Call parent class stuff.
        super(OTPmeLock, self).__init__(lock_type, lock_id, write=write)
        self.write = write
        self.cluster = cluster
        self.callback = callback

        # Get logger.
        self.logger = config.logger

        self._lock_type = "read"
        if self.write:
            self._lock_type = "write"

        lock_id = oid_to_fs_name(self.lock_id)
        self.lock_file = ("%s/%s" % (config.locks_dir, lock_id))
        self.flock = self.get_flock()

    #def __getattr__(self, name):
    #    """ Map to original attributes. """
    #    return getattr(self.flock, name)

    def __str__(self):
        x_str = ",".join(self.lock_callers)
        x_str = "%s (%s) (%s)" % (self.lock_id, self._lock_type, x_str)
        return x_str

    def get_lock_age(self):
        """ Get age of the current lock. """
        now = time.time()
        try:
            last_mod_time = os.path.getmtime(self.lock_file)
        except FileNotFoundError:
            last_mod_time = time.time()
        lock_age = now - last_mod_time
        return lock_age

    def get_flock(self):
        from otpme.lib import config
        user = config.user
        group = config.group
        fd = AtomicFileLock(path=self.lock_file,
                            user=user,
                            group=group,
                            mode="w",
                            register=remember_fd,
                            unregister=forget_fd)
        fd.write(str(self.lock_id)+"\n")
        fd.flush()
        return fd

    def acquire_lock(self, lock_caller=None, skip_same_caller=False, timeout=None):
        """ Acquire lock. """
        from otpme.lib import config
        #from otpme.lib.daemon.clusterd import cluster_object_lock
        # Set default lock caller.
        if lock_caller is None:
            lock_caller = self.lock_id
        if not self.lock_callers:
            wait_message = "Waiting for lock: %s" % self.lock_id

            #if self.cluster:
            #    try:
            #        cluster_object_lock(action="lock",
            #                            lock_type=self.lock_type,
            #                            lock_id=self._lock_id,
            #                            write=self.write,
            #                            timeout=timeout)
            #    except LockWaitTimeout:
            #        msg = "Failed to acquire lock: %s" % self._lock_id
            #        #self.flock.release_lock()
            #        raise LockWaitTimeout(msg)

            block = True
            if timeout == 0:
                block = False
            if self.write:
                lock_status = self.flock.acquire_lock(block=block,
                                                    exclusive=True,
                                                    timeout=timeout,
                                                    wait_message=wait_message,
                                                    log_wait_message=True,
                                                    callback=self.callback)
            else:
                lock_status = self.flock.acquire_lock(block=block,
                                                    timeout=timeout,
                                                    wait_message=wait_message,
                                                    log_wait_message=True,
                                                    callback=self.callback)
            if not lock_status:
                raise LockWaitTimeout()

            if config.debug_level("locking") > 1:
                msg = ("Acquired lock: %s (%s): %s"
                    % (self.lock_id, self._lock_type, self.lock_file))
                self.logger.debug(msg)

        super(OTPmeLock, self).acquire_lock(lock_caller=lock_caller,
                                        skip_same_caller=skip_same_caller)

    def release_lock(self, lock_caller=None, force=False):
        """ Release lock"""
        from otpme.lib import config
        #from otpme.lib.daemon.clusterd import cluster_object_lock
        if lock_caller is None:
            if force:
                ## Release cluster lock.
                #if self.cluster:
                #    cluster_object_lock(action="release",
                #                        lock_type=self.lock_type,
                #                        lock_id=self._lock_id,
                #                        write=self.write)
                # Make sure we empty lock callers on force.
                self.lock_callers = []
                # Release lock.
                self.flock.release_lock()
                # Try to remove the lock file if its not used anymore.
                self.flock.unlink()
                # Close flock.
                self.flock.close()
                return
            lock_caller = self.lock_id

        # Call parent class stuff.
        super(OTPmeLock, self).release_lock(lock_caller=lock_caller,
                                                _forget_lock=False)

        # We do not release the lock if there are still any open callers.
        if self.lock_callers:
            return

        # Try to remove the lock file if its not used anymore.
        self.flock.unlink()
        # Close flock.
        self.flock.close()

        ## Release cluster lock.
        #if self.cluster:
        #    cluster_object_lock(action="release",
        #                        lock_type=self.lock_type,
        #                        lock_id=self._lock_id)
        # Release flock.
        self.flock.release_lock()
        # We dont want the released lock to be re-used.
        self.forget_lock()

        if config.debug_level("locking") > 1:
            msg = ("Released lock: %s (%s): %s"
                % (self.lock_id, self._lock_type, self.lock_file))
            self.logger.debug(msg)
