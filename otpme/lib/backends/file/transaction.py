# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time
import shutil
import functools
import threading
#from functools import wraps
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
from otpme.lib import cache
from otpme.lib import config
from otpme.lib import locking
from otpme.lib import nsscache
from otpme.lib import filetools
from otpme.lib import sign_key_cache
from otpme.lib import multiprocessing
from otpme.lib.classes.object_config import ObjectConfig

from otpme.lib.exceptions import *

#thread_locks = {}
current_job_transactions = {}
#session_lock = threading.Lock()
default_callback = config.get_callback()

logger = config.logger
#DB_LOCK_TYPE = "db_session"
F_TRANSACTION_LOCK_TYPE = "transaction.file"
I_TRANSACTION_LOCK_TYPE = "transaction.index"
O_TRANSACTION_LOCK_TYPE = "transaction.object"

DEBUG_SLOT = "transactions"
FILE_TRANSACTIONS_DIR = os.path.join(config.transaction_dir, "files")
OBJECT_TRANSACTIONS_DIR = os.path.join(config.transaction_dir, "objects")

# Make sure transaction directories exists.
transaction_dirs = [
                FILE_TRANSACTIONS_DIR,
                OBJECT_TRANSACTIONS_DIR,
                ]

#locking.register_lock_type(DB_LOCK_TYPE, module=__file__)
locking.register_lock_type(F_TRANSACTION_LOCK_TYPE, module=__file__)
locking.register_lock_type(I_TRANSACTION_LOCK_TYPE, module=__file__)
locking.register_lock_type(O_TRANSACTION_LOCK_TYPE, module=__file__)

def init():
    """ Init transaction dirs. """
    for x in transaction_dirs:
        if os.path.exists(x):
            continue
        filetools.create_dir(path=x,
                            user=config.user,
                            group=config.group,
                            mode=0o770)
def atfork():
    global session_lock
    global current_job_transactions
    session_lock = threading.Lock()
    current_job_transactions.clear()

def cleanup():
    """ Cleanup transactions. """
    _transaction = get_transaction(active=False)
    if not _transaction:
        return
    _transaction._remove_incomplete_transaction(quiet=True)

def get_overlay_file(object_id, active=True):
    """ Build object overlay file path. """
    filename = oid.oid_to_fs_name(object_id.read_oid)
    filename = "%s.json" % filename
    overlay_file = os.path.join(OVERLAY_DIR, filename)
    if not active:
        return overlay_file
    if not os.path.exists(overlay_file):
        return
    return overlay_file

def handle_transaction(func):
    """ Decorator to handle transactions within the file backend. """
    def wrapper(*args, **kwargs):
        close_session = True
        try:
            no_transaction = kwargs.pop('no_transaction')
        except:
            no_transaction = False
        # Get transactions, even not actives anymore to use the session
        # e.g. for reading from sqlite transaction.
        use_transaction = False
        _transaction = get_transaction(active=None)
        # Transaction ID added to kwargs to get good function cache results.
        # Thats needed because results differ with an active transaction. This
        # is needed especially for shared caches.
        transaction_id = None
        if _transaction:
            transaction_id = _transaction.id
            # If we got a transaction use it.
            use_transaction = True
        # But not if we got no_transaction from kwargs.
        if no_transaction:
            use_transaction = False
            # When doing stuff without transaction but with a active transaction
            # we must keep the session open to keep any DB transaction.
            if _transaction:
                close_session = False
        # Use transaction session.
        if use_transaction:
            close_session = False
            session = _transaction.session
        else:
            _index = config.get_index_module()
            session = _index.get_db_connection()
        # Run function.
        try:
            result = func(*args, session=session,
                        transaction_id=transaction_id,
                        **kwargs)
        except:
            session.rollback()
            raise
        finally:
            if close_session:
                session.close()
        return result

    # Update func/method.
    functools.update_wrapper(wrapper, func)
    if not hasattr(wrapper, '__wrapped__'):
        # Python 2.7
        wrapper.__wrapped__ = func

    return wrapper

def get_transaction(active=True):
    """ Get transaction. """
    global current_job_transactions
    proc_id = multiprocessing.get_id()
    try:
        transaction = current_job_transactions[proc_id]
        if active is not None:
            if transaction.active != active:
                return
    except Exception as e:
        transaction = None
    return transaction

def add_transaction(transaction):
    """ Add transaction. """
    global current_job_transactions
    proc_id = multiprocessing.get_id()
    current_job_transactions[proc_id] = transaction

def remove_transaction():
    """ Remove transaction. """
    global current_job_transactions
    proc_id = multiprocessing.get_id()
    current_job_transactions.pop(proc_id)

def get_file_transactions():
    """ Get all file transaction IDs. """
    file_transactions = filetools.list_dir(FILE_TRANSACTIONS_DIR,
                                            sort_by="ctime")
    return file_transactions

def get_object_transactions():
    """ Get all object transaction UUIDs. """
    object_transactions = filetools.list_dir(OBJECT_TRANSACTIONS_DIR,
                                                sort_by="ctime")
    return object_transactions

def begin_transaction(name, callback=default_callback):
    """ Begin transaction. """
    if not config.transactions_enabled:
        return
    # Get object transaction.
    _transaction = ObjectTransaction(name=name, callback=callback)
    # Mark transaction as active.
    _transaction.active = True
    if config.debug_level(DEBUG_SLOT) > 0:
        msg = "Begin transaction: %s" % _transaction.id
        logger.debug(msg)
    # Start transaction.
    _transaction.begin()
    add_transaction(_transaction)
    if config.debug_level(DEBUG_SLOT) > 0:
        msg = "Transaction started: %s" % _transaction.id
        logger.debug(msg)
    return _transaction

def end_transaction():
    """ End transaction. """
    if not config.transactions_enabled:
        return
    # Remove transaction from list.
    _transaction = get_transaction(active=None)
    if not _transaction:
        msg = "Uhhh, tried to end not existing transaction."
        logger.warning(msg)
        return

    try:
        # Make sure cached objects are written to this transaction.
        modified_objects = _transaction.write_cached_objects()
        # Mark transaction as not active anymore.
        _transaction.active = False
        # Spool transaction.
        try:
            _transaction._write()
        except Exception as e:
            msg = "Failed to save transaction: %s: %s" % (_transaction.id, e)
            logger.critical(msg)
            config.raise_exception()
            return False
        # Commit transaction. For running transactions we dont need to modify
        # index DB anymore because of a currently active DB transaction.
        try:
            _transaction.commit()
        except Exception as e:
            msg = "Failed to end transaction: %s: %s" % (_transaction.id, e)
            logger.critical(msg, exc_info=True)
            config.raise_exception()
            return False
        # Remove transaction after successful commit.
        remove_transaction()
        # Delete transaction.
        _transaction.remove()
        # Reset modified flag.
        for o in modified_objects:
            o.reset_modified()
            cache.add_instance(o)
        # Release object locks.
        for o in _transaction.locked_objects:
            o.release_lock(lock_caller=_transaction.lock_caller)
    finally:
        _transaction.release_lock()

    if config.debug_level(DEBUG_SLOT) > 0:
        msg = "Ended transaction: %s" % _transaction.id
        logger.debug(msg)

def abort_transaction():
    """ Abort transaction. """
    if not config.transactions_enabled:
        return
    # Remove transaction from list.
    _transaction = get_transaction()
    if not _transaction:
        msg = "Uhhh, tried to abort not existing transaction."
        logger.warning(msg)
        return
    try:
        # Remove transaction.
        remove_transaction()
        # Delete transaction.
        _transaction.remove()
        # Release object locks.
        for o in _transaction.locked_objects:
            o.release_lock(lock_caller=_transaction.lock_caller)
    finally:
        _transaction.release_lock()
    if config.debug_level(DEBUG_SLOT) > 0:
        msg = "Aborted transaction: %s" % _transaction.id
        logger.debug(msg)

def replay_transactions():
    """ Replay transactions. """
    # Will not replay transactions from within controld.
    # This would lead to open posix semaphores as root.
    if config.daemon_name == "controld":
        return
    # Replay file transactions.
    for x in get_file_transactions():
        # Get transaction.
        _transaction = FileTransaction(id=x)
        # Ignore active transaction.
        if _transaction.is_active():
            if config.debug_level(DEBUG_SLOT) > 1:
                msg = ("Ignoring active transaction (file): %s"
                        % _transaction.id)
                logger.debug(msg)
            continue
        # Lock transaction.
        try:
            _transaction.acquire_lock(timeout=0.01)
        except ObjectLocked:
            continue
        try:
            # Remove finished or incomplete transaction.
            if not _transaction.exists():
                _transaction.remove()
                continue
            # Load transaction.
            try:
                _transaction.read()
            except NotFound:
                continue
            except Exception as e:
                config.raise_exception()
                msg = "Failed to load transaction: %s: %s" % (x, e)
                logger.critical(msg)
                continue
            if config.debug_level(DEBUG_SLOT) > 0:
                msg = "Replaying transaction (file): %s" % x
                logger.debug(msg)
            # Commit transaction.
            try:
                _transaction.replay()
            except Exception as e:
                config.raise_exception()
                msg = ("Failed to replay transaction: %s: %s"
                        % (_transaction.id, e))
                logger.critical(msg)
                continue
            # Delete transaction.
            _transaction.remove()
        finally:
            _transaction.release_lock()

    # Replay object transactions.
    for x in get_object_transactions():
        # Get transaction.
        _transaction = ObjectTransaction(id=x)
        # Ignore active transaction.
        if _transaction.is_active():
            if config.debug_level(DEBUG_SLOT) > 1:
                msg = ("Ignoring active transaction (object): %s"
                        % _transaction.id)
                logger.debug(msg)
            continue
        # Lock transaction.
        try:
            _transaction.acquire_lock(timeout=0.01)
        except ObjectLocked:
            continue
        try:
            # Remove finished or incomplete transaction.
            if not _transaction.exists():
                _transaction.remove()
                continue
            # Load transaction.
            try:
                _transaction.read()
            except NotFound:
                continue
            except Exception as e:
                config.raise_exception()
                msg = "Failed to load transaction: %s: %s" % (x, e)
                logger.critical(msg)
                continue
            if config.debug_level(DEBUG_SLOT) > 0:
                msg = "Replaying transaction (object): %s" % x
                logger.debug(msg)
            # Commit transaction.
            try:
                _transaction.replay()
            except Exception as e:
                config.raise_exception()
                msg = ("Failed to replay transaction: %s: %s"
                        % (_transaction.id, e))
                logger.critical(msg)
                continue
            # Delete transaction.
            _transaction.remove()
        finally:
            _transaction.release_lock()

def transaction(func):
    """ Decorator to handle transaction for class method. """
    def wrapper(*args, **kwargs):
        try:
            callback = kwargs['callback']
        except:
            callback = default_callback
        start_transaction = True
        if not config.transactions_enabled:
            start_transaction = False
        # Make sure we do not try to start another transaction
        # (e.g. on recursive method call).
        _transaction = get_transaction()
        if _transaction:
            start_transaction = False
        if start_transaction:
            proc_id = multiprocessing.get_id()
            if proc_id is None:
                msg = "Transaction failed: Unable to get process/thread name."
                raise OTPmeException(msg)
            begin_transaction(proc_id, callback=callback)
        # Run function.
        result = func(*args, **kwargs)
        if start_transaction:
            if result is False:
                abort_transaction()
            else:
                end_transaction()
        return result

    # Update func/method.
    functools.update_wrapper(wrapper, func)
    if not hasattr(wrapper, '__wrapped__'):
        # Python 2.7
        wrapper.__wrapped__ = func

    return wrapper

class BaseTransaction(object):
    """ Base transaction. """
    def __init__(self, transaction_type, name=None, id=None, uuid=None, lock_type=None,
        no_disk_writes=False, no_index_writes=False, **kwargs):
        if id:
            self.id = id
            self.uuid = id.split(":")[1]
            self.pid = id.split(":")[2]
        else:
            if uuid:
                self.uuid = uuid
            else:
                self.uuid = stuff.gen_uuid()
            # Set PID of writing process.
            self.pid = os.getpid()
            self.id = "%s:%s:%s" % (time.time(), self.uuid, self.pid)
        self.name = name
        self.status = "new"
        self._lock = None
        self._replay = False
        self.lock_type = lock_type
        self.journal = []
        self.journal_entries = {}
        # We do not use 0 as start because sorting files by name will end in
        # wrong order (e.g. 0 10 11 12 ...).
        self.journal_counter = 1000
        self.journal_file_extension = "action"
        # If no disk writes is enabled we will not do any changes on
        # disk but add/del objects to/from index DB (without commit).
        self.no_disk_writes = no_disk_writes
        # If no index writes is enabled we will skip any DB operation.
        self.no_index_writes = no_index_writes
        self.transaction_type = transaction_type
        if self.name:
            self.log_name = ("%s: %s (%s)"
                            % (self.transaction_type,
                            self.name, self.id))
        else:
            self.log_name = "%s: %s" % (self.transaction_type, self.id)
        self.compression = "lz4"

    def index_add(self, object_id, **kwargs):
        """ Add OID to index. """
        action = "index_add"
        journal_file = self.get_journal_file(action)
        journal_entry = {
                        'action'        : action,
                        'object_id'     : object_id.full_oid,
                        'kwargs'        : kwargs,
                        'journal_file'  : journal_file,
                        }
        self.journal.append(self.journal_counter)
        self.journal_entries[str(self.journal_counter)] = journal_entry
        self.journal_counter += 1

    def index_del(self, object_id, **kwargs):
        """ Delete OID from index. """
        action = "index_del"
        journal_file = self.get_journal_file(action)
        journal_entry = {
                        'action'        : action,
                        'object_id'     : object_id.full_oid,
                        'kwargs'        : kwargs,
                        'journal_file'  : journal_file,
                        }
        self.journal.append(self.journal_counter)
        self.journal_entries[str(self.journal_counter)] = journal_entry
        self.journal_counter += 1

    def _index_add(self, object_id, **kwargs):
        """ Add object to index. """
        from .file import index_add
        try:
            index_add(object_id, **kwargs)
        except Exception as e:
            msg = ("Error creating index for object: %(object_id)s: %(error)s"
                % {"object_id":object_id, "error":e})
            logger.critical(msg)
            config.raise_exception()
            return

    def _index_del(self, object_id, **kwargs):
        """ Remove object from index. """
        from .file import index_del
        try:
            index_del(object_id, **kwargs)
        except Exception as e:
            msg = ("Error removing index for object: %(object_id)s: %(error)s"
                % {"object_id":object_id, "error":e})
            logger.critical(msg)
            config.raise_exception()

    def exists(self):
        """ Check if transaction exists. """
        if os.path.exists(self.status_file):
            return True
        return False

    def begin(self):
        """ Start transaction. """
        self.set_status("new")
        self.acquire_lock()

    def acquire_lock(self, **kwargs):
        """ Lock transaction. """
        try:
            self._lock = locking.acquire_lock(lock_type=self.lock_type,
                                                lock_id=self.id,
                                                **kwargs)
        except LockWaitTimeout:
            msg = "Transaction is locked: %s (%s)" % (self.id, self.lock_type)
            raise ObjectLocked(msg)

    def release_lock(self):
        """ Release transaction lock. """
        if not self._lock:
            msg = "Tried to release released transaction lock."
            raise OTPmeException(msg)
        self._lock.release_lock()

    def _write_object_file(self, config_file, object_config, full_data_update=None):
        """ Write object data to file. """
        # Try to write object file.
        try:
            filetools.write_data_file(filename=config_file,
                                    object_config=object_config,
                                    full_data_update=full_data_update,
                                    user=config.user,
                                    group=config.group,
                                    mode=0o770)
        except Exception as e:
            msg = ("Error writing config file: %s" % e)
            logger.critical(msg)
            config.raise_exception()

    def get_journal_file(self, action):
        """ Build journal spool file path. """
        filename = ("%s-%s.%s" % (self.journal_counter, action,
                                self.journal_file_extension))
        journal_file = os.path.join(self.journal_dir, filename)
        return journal_file

    def _remove_incomplete_transaction(self, ignore_status=False, quiet=False):
        """ Remove incomplete (written to disk) transaction. """
        if self.no_disk_writes:
            return
        incomplete = False
        if not ignore_status:
            if self.status != "written":
                incomplete = True
        if os.path.exists(self.status_file):
            if os.path.getsize(self.status_file) == 0:
                incomplete = True
        else:
            incomplete = True
        if incomplete:
            if not quiet:
                msg = "Removing incomplete transaction: %s" % self.log_name
                logger.debug(msg)
            self.remove()
        return incomplete

    def is_active(self):
        """ Check if transaction (process) is active. """
        if self.pid is None:
            msg = "Uuuuh, missing transaction PID: %s" % self.log_name
            raise OTPmeException(msg)
        if stuff.check_pid(self.pid):
            return True
        return False

    def set_status(self, status):
        """ Write transaction status to disk. """
        # Set status.
        self.status = status
        # Transaction meta data.
        transaction_meta = ("%s;%s;%s" % (self.status, self.name, self.uuid))
        # Create spool directory.
        if not os.path.exists(self.spool_dir):
            self._create_dir(self.spool_dir)
        # Write status file.
        filetools.create_file(path=self.status_file,
                            content=transaction_meta,
                            user=config.user,
                            group=config.group,
                            mode=0o660)
    def read(self):
        """ Read transaction from disk. """
        if self._remove_incomplete_transaction(ignore_status=True):
            raise NotFound()
        # Read transaction name.
        try:
            status_data = filetools.read_file(self.status_file)
        except Exception as e:
            msg = ("Error reading transaction status: %s: %s"
                    % (self.status_file, e))
            raise OTPmeException(msg)
        # Decode transaction meta data.
        try:
            self.status, \
            self.name, \
            self.uuid = status_data.split(";")
            msg = ("Invalid transaction status data: %s" % status_data)
            if self.status is None:
                raise OTPmeException(msg)
            if self.pid is None:
                raise OTPmeException(msg)
            if self.name is None:
                raise OTPmeException(msg)
        except Exception as e:
            msg = ("Error decoding transaction status data: %s: %s"
                    % (self.status_file, e))
            raise OTPmeException(msg)

        # Break if transaction is incomplete.
        if self.status != "written":
            if not self.is_active():
                self.remove()
            raise NotFound()

        # Read transaction journal.
        journal_files = []
        files_sorted = filetools.list_dir(self.journal_dir)
        for x in sorted(files_sorted):
            journal_file = os.path.join(self.journal_dir, x)
            journal_files.append(journal_file)
        # No journal, no transaction.
        if not journal_files:
            self._remove_incomplete_transaction()
            return

        for x in journal_files:
            if config.debug_level(DEBUG_SLOT) > 3:
                msg = "Reading transaction data from disk: %s" % x
                logger.debug(msg)
            try:
                file_content = filetools.read_file(path=x,
                                                read_mode="rb",
                                                compression=self.compression)
            except Exception as e:
                config.raise_exception()
                msg = ("Error reading transaction: %s: %s" % (x, e))
                raise OTPmeException(msg)

            journal_entry = json.loads(file_content)

            self.journal.append(self.journal_counter)
            self.journal_entries[str(self.journal_counter)] = journal_entry
            self.journal_counter += 1

    def _write_journal(self):
        """ Write transaction journal to disk. """
        # No need to write empty transaction to disk.
        if self.journal_counter == 0:
            msg = "Not writing emtpy transaction to disk: %s" % self.log_name
            if config.debug_level(DEBUG_SLOT) > 0:
                logger.debug(msg)
            raise EmptyTransaction(msg)

        if config.debug_level(DEBUG_SLOT) > 3:
            msg = ("Writing transaction to disk: %s" % self.spool_dir)
            logger.debug(msg)

        # Mark transaction as currently saving to disk.
        self.set_status("saving")

        if not os.path.exists(self.journal_dir):
            self._create_dir(self.journal_dir)

        # Write transaction.
        for x in self.journal:
            # Get journal entry.
            journal_entry = self.journal_entries[str(x)]
            # Encode data.
            file_content = json.dumps(journal_entry)
            # Get spool file.
            journal_file = journal_entry['journal_file']

            if config.debug_level(DEBUG_SLOT) > 3:
                msg = ("Writing transaction data to disk: %s (%s)"
                        % (journal_file, self.name))
                logger.debug(msg)

            # Write object to spool file.
            filetools.create_file(path=journal_file,
                                content=file_content,
                                user=config.user,
                                group=config.group,
                                mode=0o660,
                                compression=self.compression)
    def _write(self):
        """ Write transaction to disk. """
        # Mark transaction as completely written to disk.
        self.set_status("written")
        if config.debug_level(DEBUG_SLOT) > 3:
            msg = "Transaction succesfully written to disk: %s" % self.log_name
            logger.debug(msg)

    def _create_dir(self, directory):
        """ Create dir. """
        if os.path.exists(directory):
            return
        try:
            filetools.create_dir(path=directory,
                                user=config.user,
                                group=config.group,
                                mode=0o770)
        except FileExistsError:
            pass
        except Exception as e:
            msg = "Error creating directory: %s" % e
            logger.critical(msg)
            config.raise_exception()

    def _remove_file(self, filepath):
        """ Remove file. """
        if not os.path.islink(filepath):
            if not os.path.exists(filepath):
                return
        try:
            filetools.delete(filepath)
        except Exception as e:
            msg = (_("Error removing file '%(file)s: %(error)s")
                            % {"file":filepath, "error":e})
            logger.critical(msg)
            config.raise_exception()

    def remove(self):
        """ Delete transaction spool directory. """
        if not os.path.exists(self.spool_dir):
            return
        if config.debug_level(DEBUG_SLOT) > 3:
            msg = "Removing transaction: %s" % self.log_name
            logger.debug(msg)
        try:
            shutil.rmtree(self.spool_dir)
        except Exception as e:
            msg = "Failed to remove transaction: %s" % e
            logger.critical(msg)

class FileTransaction(BaseTransaction):
    """ File backend write transaction. """
    def __init__(self, name=None, id=None, commit_files=None, **kwargs):
        super(FileTransaction, self).__init__("file", name=name, id=id,
                            lock_type=F_TRANSACTION_LOCK_TYPE, **kwargs)
        self.spool_dir = os.path.join(FILE_TRANSACTIONS_DIR, self.id)
        self.journal_dir = os.path.join(self.spool_dir, "journal")
        self.commits_dir = os.path.join(self.spool_dir, "parents")
        self.status_file = os.path.join(self.spool_dir, "transaction.status")
        self.commit_files = commit_files

    def begin(self):
        """ Start transaction. """
        object_transaction = get_transaction(active=None)
        if object_transaction:
            object_transaction.add_file_transaction(self)
        # Call parent class method.
        super(FileTransaction, self).begin()
        if not self.commit_files:
            return
        for x in self.commit_files:
            self.add_commit_file(x)

    def add_commit_file(self, commit_file):
        """ Add commit file to transaction. """
        x_filename = stuff.gen_md5(commit_file)
        x_commit_file = os.path.join(self.commits_dir, x_filename)
        if os.path.exists(x_commit_file):
            return
        if not os.path.exists(self.commits_dir):
            self._create_dir(self.commits_dir)
        try:
            filetools.symlink(commit_file, x_commit_file)
        except Exception as e:
            msg = ("Failed to add commit file: %s: %s" % (commit_file, e))
            logger.critical(msg)

    def _write(self):
        """ Write file transaction to disk. """
        # Will ignore emtpy transaction.
        try:
            self._write_journal()
        except EmptyTransaction:
            return
        # Call parent class write method to finalize write.
        return super(FileTransaction, self)._write()

    def cluster_write(self, object_uuid, object_id, index_journal, object_config):
        """ Cluster write action. """
        action = "cluster_write"
        journal_file = self.get_journal_file(action)
        journal_entry = {
                        'action'        : action,
                        'object_uuid'   : object_uuid,
                        'object_id'     : object_id.full_oid,
                        'index_journal' : index_journal,
                        'object_config' : object_config,
                        'journal_file'  : journal_file,
                        }
        self.journal.append(self.journal_counter)
        self.journal_entries[str(self.journal_counter)] = journal_entry
        self.journal_counter += 1

    def cluster_delete(self, object_uuid, object_id):
        """ Cluster delete action. """
        action = "cluster_delete"
        journal_file = self.get_journal_file(action)
        journal_entry = {
                        'action'        : action,
                        'object_uuid'   : object_uuid,
                        'object_id'     : object_id.full_oid,
                        'journal_file'  : journal_file,
                        }
        self.journal.append(self.journal_counter)
        self.journal_entries[str(self.journal_counter)] = journal_entry
        self.journal_counter += 1

    def cluster_rename(self, object_uuid, object_id, new_object_id):
        """ Cluster rename action. """
        action = "cluster_rename"
        journal_file = self.get_journal_file(action)
        journal_entry = {
                        'action'        : action,
                        'object_id'     : object_id.full_oid,
                        'object_uuid'   : object_uuid,
                        'new_object_id' : new_object_id.full_oid,
                        'journal_file'  : journal_file,
                        }
        self.journal.append(self.journal_counter)
        self.journal_entries[str(self.journal_counter)] = journal_entry
        self.journal_counter += 1

    def write_object_file(self, config_file, object_config, full_data_update=None):
        """ Write object config file. """
        action = "write_object_file"
        journal_file = self.get_journal_file(action)
        journal_entry = {
                        'action'            : action,
                        'config_file'       : config_file,
                        'object_config'     : object_config,
                        'journal_file'      : journal_file,
                        'full_data_update'  : full_data_update,
                        }
        self.journal.append(self.journal_counter)
        self.journal_entries[str(self.journal_counter)] = journal_entry
        self.journal_counter += 1

    def create_dir(self, directory):
        """ Create directory. """
        action = "create_dir"
        journal_file = self.get_journal_file(action)
        journal_entry = {
                        'action'        : action,
                        'directory'     : directory,
                        'journal_file'  : journal_file,
                        }
        self.journal.append(self.journal_counter)
        self.journal_entries[str(self.journal_counter)] = journal_entry
        self.journal_counter += 1

    def move(self, src_dir, dst_dir):
        """ Move directory. """
        action = "move"
        journal_file = self.get_journal_file(action)
        journal_entry = {
                        'action'        : action,
                        'src_dir'       : src_dir,
                        'dst_dir'       : dst_dir,
                        'journal_file'  : journal_file,
                        }
        self.journal.append(self.journal_counter)
        self.journal_entries[str(self.journal_counter)] = journal_entry
        self.journal_counter += 1

    def remove_dir(self, directory, **kwargs):
        """ Move directory. """
        action = "remove_dir"
        journal_file = self.get_journal_file(action)
        journal_entry = {
                        'action'        : action,
                        'directory'     : directory,
                        'kwargs'        : kwargs,
                        'journal_file'  : journal_file,
                        }
        self.journal.append(self.journal_counter)
        self.journal_entries[str(self.journal_counter)] = journal_entry
        self.journal_counter += 1

    def remove_file(self, filepath, **kwargs):
        """ Move file. """
        action = "remove_file"
        journal_file = self.get_journal_file(action)
        journal_entry = {
                        'action'        : action,
                        'filepath'      : filepath,
                        'kwargs'        : kwargs,
                        'journal_file'  : journal_file,
                        }
        self.journal.append(self.journal_counter)
        self.journal_entries[str(self.journal_counter)] = journal_entry
        self.journal_counter += 1

    def update_nsscache(self, object_id, nsscache_action):
        """ Update object in nsscache. """
        action = "update_nsscache"
        journal_file = self.get_journal_file(action)
        journal_entry = {
                        'action'            : action,
                        'nsscache_action'   : nsscache_action,
                        'object_id'         : object_id.full_oid,
                        'journal_file'      : journal_file,
                    }
        self.journal_entries[str(self.journal_counter)] = journal_entry
        self.journal.append(self.journal_counter)
        self.journal_counter += 1

    def _move(self, src_dir, dst_dir):
        """ Move directory. """
        if self._replay:
            if not os.path.exists(src_dir):
                if os.path.exists(dst_dir):
                    return
        try:
            shutil.move(src_dir, dst_dir)
        except Exception as e:
            msg = ("Error renaming directory: %s > %s: %s"
                    % (src_dir, dst_dir, e))
            logger.critical(msg)
            config.raise_exception()

    def _remove_dir(self, directory, recursive=False, remove_non_empty=False):
        """ Remove directory. """
        if not os.path.exists(directory):
            return
        try:
            filetools.remove_dir(directory,
                            recursive=recursive,
                            remove_non_empty=remove_non_empty)
        except Exception as e:
            msg = (_("Error removing directory '%(dir)s: %(error)s")
                            % {"dir":directory, "error":e})
            logger.critical(msg)
            config.raise_exception()

    def _update_nsscache(self, object_id, nsscache_action):
        """ Update nsscache. """
        try:
            nsscache.update_object(object_id, nsscache_action)
        except Exception as e:
            msg = (_("Error while nsscache action '%(nsscache_action)s: %(error)s")
                        % {"nsscache_action":nsscache_action, "error":e})
            logger.critical(msg)
            config.raise_exception()

    def commit(self, **kwargs):
        """ Commit write and commit journal. """
        if not self.no_disk_writes:
            if self.status != "written":
                self._write()
        try:
            result = self._commit(**kwargs)
        except Exception as e:
            msg = "Failed to commit transaction: %s: %s" % (self.log_name, e)
            config.raise_exception()
            raise OTPmeException(msg)
        return result

    def _commit(self):
        """ Commit journal. """
        from otpme.lib.daemon.clusterd import cluster_sync_object
        # Remove incomplete (written to disk) transaction.
        if self._remove_incomplete_transaction():
            return

        if config.debug_level(DEBUG_SLOT) > 3:
            msg = "Commiting transaction: %s" % self.log_name
            logger.debug(msg)

        cluster_events = []
        for x in self.journal:
            journal_entry = self.journal_entries[str(x)]
            action = journal_entry['action']
            journal_file = journal_entry['journal_file']

            if config.debug_level(DEBUG_SLOT) > 4:
                msg = "Applying action: %s: %s" % (action, self.log_name)
                logger.debug(msg)

            if action == "index_add":
                if not self.no_index_writes:
                    object_id = journal_entry['object_id']
                    object_id = oid.get(object_id)
                    kwargs = journal_entry['kwargs']
                    autocommit = True
                    if self.no_disk_writes:
                        autocommit = False
                    kwargs['autocommit'] = autocommit
                    self._index_add(object_id, **kwargs)
            elif action == "index_del":
                if not self.no_index_writes:
                    object_id = journal_entry['object_id']
                    object_id = oid.get(object_id)
                    kwargs = journal_entry['kwargs']
                    autocommit = True
                    if self.no_disk_writes:
                        autocommit = False
                    kwargs['autocommit'] = autocommit
                    self._index_del(object_id, **kwargs)
            elif action == "create_dir":
                if not self.no_disk_writes:
                    directory = journal_entry['directory']
                    self._create_dir(directory)
            elif action == "write_object_file":
                if not self.no_disk_writes:
                    config_file = journal_entry['config_file']
                    object_config = journal_entry['object_config']
                    full_data_update = journal_entry['full_data_update']
                    self._write_object_file(config_file, object_config,
                                        full_data_update=full_data_update)
            elif action == "move":
                if not self.no_disk_writes:
                    src_dir = journal_entry['src_dir']
                    dst_dir = journal_entry['dst_dir']
                    self._move(src_dir, dst_dir)
            elif action == "remove_dir":
                if not self.no_disk_writes:
                    kwargs = journal_entry['kwargs']
                    directory = journal_entry['directory']
                    self._remove_dir(directory, **kwargs)
            elif action == "remove_file":
                if not self.no_disk_writes:
                    filepath = journal_entry['filepath']
                    self._remove_file(filepath)
            elif action == "update_nsscache":
                if not self.no_disk_writes:
                    object_id = journal_entry['object_id']
                    object_id = oid.get(object_id)
                    nsscache_action = journal_entry['nsscache_action']
                    self._update_nsscache(object_id, nsscache_action)
            elif action == "cluster_write":
                if not self.no_disk_writes:
                    object_config = journal_entry['object_config']
                    index_journal = journal_entry['index_journal']
                    object_uuid = journal_entry['object_uuid']
                    object_id = journal_entry['object_id']
                    object_id = oid.get(object_id)
                    ## Get current object config.
                    #object_config = read(object_id)
                    object_config = ObjectConfig(object_id, object_config)
                    # Decrypt object config.
                    object_config = object_config.decrypt(config.master_key)
                    object_checksum = object_config['CHECKSUM']
                    wait_for_write = True
                    if self._replay:
                        wait_for_write = False
                    cluster_event = cluster_sync_object(object_uuid=object_uuid,
                                                    object_id=object_id,
                                                    object_config=object_config,
                                                    action="write",
                                                    checksum=object_checksum,
                                                    index_journal=index_journal,
                                                    wait_for_write=wait_for_write)
                    if cluster_event:
                        cluster_events.append(cluster_event)
            elif action == "cluster_delete":
                if not self.no_disk_writes:
                    object_uuid = journal_entry['object_uuid']
                    object_id = journal_entry['object_id']
                    object_id = oid.get(object_id)
                    wait_for_write = True
                    if self._replay:
                        wait_for_write = False
                    cluster_event = cluster_sync_object(object_uuid=object_uuid,
                                                        object_id=object_id,
                                                        action="delete",
                                                        wait_for_write=wait_for_write)
                    if cluster_event:
                        cluster_events.append(cluster_event)
            elif action == "cluster_rename":
                if not self.no_disk_writes:
                    object_id = journal_entry['object_id']
                    object_id = oid.get(object_id)
                    object_uuid = journal_entry['object_uuid']
                    new_object_id = journal_entry['new_object_id']
                    new_object_id = oid.get(new_object_id)
                    wait_for_write = True
                    if self._replay:
                        wait_for_write = False
                    cluster_event = cluster_sync_object(object_uuid=object_uuid,
                                                        object_id=object_id,
                                                        action="rename",
                                                        new_object_id=new_object_id,
                                                        wait_for_write=wait_for_write)
                    if cluster_event:
                        cluster_events.append(cluster_event)
            else:
                msg = "Unknown transaction action: %s" % action
                raise OTPmeException(msg)

            if not self.no_disk_writes:
                self._remove_file(journal_file)

        for x in cluster_events:
            x.wait()
            x.unlink()

        if not self.no_disk_writes:
            # Remove commit files we got from object transaction.
            self.remove_commit_files()

    def replay(self, **kwargs):
        """ Replay transaction. """
        self._replay = True
        try:
            result = self._commit(**kwargs)
        except Exception as e:
            msg = "Failed to replay transaction: %s: %s" % (self.log_name, e)
            config.raise_exception()
            raise OTPmeException(msg)
        finally:
            self._replay = False
        return result

    def remove_commit_files(self):
        """ Remove commit files (e.g. object transaction journal files). """
        if self.no_disk_writes:
            return
        try:
            commit_files = filetools.list_dir(self.commits_dir)
        except:
            commit_files = []
        for x in commit_files:
            commit_link = os.path.join(self.commits_dir, x)
            if os.path.exists(commit_link):
                # Get symlink destination. We use readlink() instead of
                # realpath() because the symlink may be a symlink to another
                # symlink (e.g. overlay object).
                commit_file = os.readlink(commit_link)
                self._remove_file(commit_file)
            self._remove_file(commit_link)

    def remove(self):
        """ Delete transaction. """
        self.remove_commit_files()
        return super(FileTransaction, self).remove()

class ObjectTransaction(BaseTransaction):
    """ Object transaction. """
    def __init__(self, name=None, id=None, callback=default_callback, **kwargs):
        super(ObjectTransaction, self).__init__("object", name=name, id=id,
                            lock_type=O_TRANSACTION_LOCK_TYPE, **kwargs)
        self.spool_dir = os.path.join(OBJECT_TRANSACTIONS_DIR, self.id)
        self.journal_dir = os.path.join(self.spool_dir, "journal")
        self.deleted_objects_dir = os.path.join(self.spool_dir, "deleted")
        self.status_file = os.path.join(self.spool_dir, "transaction.status")
        # Indicates active transaction.
        self.active = False
        self.encoding = None
        # Transaction journal.
        self.journal_objects = {}
        self.journal_oid_uuid = {}
        # Modified objects.
        self.modified_objects = []
        self.locked_objects = []
        self.lock_caller = "transaction"
        self.callback = callback
        # Sign cache.
        self.sign_cache = {}
        # File transactions.
        self.file_transactions = []
        # Get DB session.
        _index = config.get_index_module()
        self.session = _index.get_db_connection()

    def add_file_transaction(self, transaction):
        self.file_transactions.append(transaction)

    def index_add(self, *args, **kwargs):
        # Add action to journal.
        super(ObjectTransaction, self).index_add(*args, **kwargs)
        # Disable autocommit.
        kwargs['autocommit'] = False
        # Add object to index.
        return self._index_add(*args, **kwargs)

    def index_del(self, *args, **kwargs):
        # Add action to journal.
        super(ObjectTransaction, self).index_del(*args, **kwargs)
        # Disable autocommit.
        kwargs['autocommit'] = False
        # Delete object from index.
        return self._index_del(*args, **kwargs)

    def cache_modified_object(self, o):
        """ Add modified object to transaction cache. """
        # Make sure OID cache is up to date.
        if o.uuid:
            self.journal_oid_uuid[o.uuid] = o.oid.full_oid
            self.journal_oid_uuid[o.oid.read_oid] = o.uuid
        if o.oid in self.modified_objects:
            return
        self.modified_objects.append(o.oid)

    def cache_locked_object(self, o):
        """ Add locked object to transaction cache. """
        if o in self.locked_objects:
            return
        self.locked_objects.append(o)

    def add_sign_cache(self, object_id, user_uuid, signer_key, **kwargs):
        """ Add public key to transaction. """
        action = "add_sign_cache"
        if config.debug_level(DEBUG_SLOT) > 4:
            msg = ("Transaction action: %s: %s: %s"
                % (action, object_id, self.log_name))
            logger.debug(msg)
        # Get spool file.
        journal_file = self.get_journal_file(action)
        # Add key to transaction sign cache.
        self.sign_cache[user_uuid] = signer_key
        # Add journal entry.
        journal_entry = {
                        'action'        : action,
                        'object_id'     : object_id.full_oid,
                        'user_uuid'     : user_uuid,
                        'kwargs'        : kwargs,
                        'journal_file'  : journal_file,
                    }
        self.journal_entries[str(self.journal_counter)] = journal_entry
        self.journal.append(self.journal_counter)
        self.journal_counter += 1

    def get_sign_cache(self, object_id, user_uuid, **kwargs):
        """ Add public key to transaction. """
        action = "get_sign_cache"
        if config.debug_level(DEBUG_SLOT) > 4:
            msg = ("Transaction action: %s: %s: %s"
                % (action, object_id, self.log_name))
            logger.debug(msg)
        # Try to get key.
        try:
            signer_key = self.sign_cache[user_uuid]
        except:
            signer_key = None
        return signer_key

    def del_sign_cache(self, object_id, user_uuid, **kwargs):
        """ Del public key from transaction. """
        action = "del_sign_cache"
        if config.debug_level(DEBUG_SLOT) > 4:
            msg = ("Transaction action: %s: %s: %s"
                % (action, object_id, self.log_name))
            logger.debug(msg)
        # Del key from transaction sign cache.
        try:
            self.sign_cache.pop(user_uuid)
        except:
            pass
        # Get spool file.
        journal_file = self.get_journal_file(action)
        # Add journal entry.
        journal_entry = {
                        'action'        : action,
                        'object_id'     : object_id.full_oid,
                        'user_uuid'     : user_uuid,
                        'kwargs'        : kwargs,
                        'journal_file'  : journal_file,
                    }
        self.journal_entries[str(self.journal_counter)] = journal_entry
        self.journal.append(self.journal_counter)
        self.journal_counter += 1

    def write_cached_objects(self):
        """ Write cached objects. """
        from otpme.lib import cache
        cached_objects = []
        for object_id in list(self.modified_objects):
            o = cache.get_modified_object(object_id)
            cache.remove_modified_object(object_id)
            #self.modified_objects.remove(object_id)
            if not o or not o._modified:
                continue
            cached_objects.append(o)
        if config.debug_level(DEBUG_SLOT) > 0:
            if cached_objects:
                msg = "Writing cached transaction objects..."
                logger.debug(msg)
        modified_objects = []
        for o in cached_objects:
            if not o._modified:
                continue
            if config.debug_level(DEBUG_SLOT) > 0:
                msg = "Writing cached object: %s: %s" % (o, self.log_name)
                logger.debug(msg)
            # Write modified object.
            try:
                o._write(callback=self.callback)
            except Exception as e:
                msg = "Failed to write object: %s: %s" % (o, e)
                logger.critical(msg)
                raise
            modified_objects.append(o.oid)
        if cached_objects:
            if config.debug_level(DEBUG_SLOT) > 0:
                msg = ("Written %s cached objects: %s"
                    % (len(modified_objects), self.log_name))
                logger.debug(msg)
        return set(cached_objects)

    def get_oid(self, uuid, full=True, instance=False):
        """ Get OID of object. """
        try:
            full_oid = self.journal_oid_uuid[uuid]
        except:
            return
        need_instance = False
        if not full:
            need_instance = True
        if instance:
            need_instance = True
        if need_instance:
            x_oid = oid.get(full_oid)
        if instance:
            return x_oid
        if not full:
            return x_oid.read_oid
        return full_oid

    def _add_object(self, object_id, object_config):
        """ Add object to journal. """
        read_oid = object_id.read_oid
        full_oid = object_id.full_oid
        try:
            object_configs = self.journal_objects[read_oid]
        except KeyError:
            object_configs = []
        # Make sure we use a copy to prevent changing of object config
        # while its cached.
        object_config = stuff.copy_object(object_config)
        object_configs.append(object_config)
        self.journal_objects[read_oid] = object_configs
        # Handle UUID/OID mapping.
        try:
            object_uuid = x_oc['UUID']
        except:
            return
        self.journal_oid_uuid[object_uuid] = full_oid
        self.journal_oid_uuid[read_oid] = object_uuid

    def dismiss_object(self, object_id):
        """ Remove object from journal. """
        read_oid = object_id.read_oid
        full_oid = object_id.full_oid
        for x in list(self.journal):
            journal_entry = self.journal_entries[str(x)]
            try:
                x_oid = journal_entry['object_id']
            except:
                continue
            if x_oid != full_oid:
                continue
            self.journal.remove(x)
        try:
            self.modified_objects.remove(object_id)
        except:
            pass
        try:
            self.journal_objects.pop(read_oid)
        except:
            pass
        try:
            object_uuid = self.journal_oid_uuid.pop(read_oid)
            self.journal_oid_uuid.pop(object_uuid)
        except:
            pass

    def add_object(self, object_id, object_config, **kwargs):
        """ Add object to transaction. """
        action = "add"
        if config.debug_level(DEBUG_SLOT) > 4:
            msg = ("Transaction action: %s: %s: %s"
                % (action, object_id, self.log_name))
            logger.debug(msg)
        # Get spool file.
        journal_file = self.get_journal_file(action)
        # Add object.
        self._add_object(object_id, object_config)
        # Add journal entry.
        journal_entry = {
                        'action'        : action,
                        'object_id'     : object_id.full_oid,
                        'object_config' : object_config,
                        'kwargs'        : kwargs,
                        'journal_file'  : journal_file,
                    }
        self.journal_entries[str(self.journal_counter)] = journal_entry
        self.journal.append(self.journal_counter)
        self.journal_counter += 1

    def get_object(self, object_id, parameters=None):
        """ Get object from transaction. """
        action = "get"
        if config.debug_level(DEBUG_SLOT) > 4:
            msg = ("Transaction action: %s: %s: %s"
                % (action, object_id, self.log_name))
            logger.debug(msg)
        read_oid = object_id.read_oid
        # Try to get object from cache.
        try:
            object_config = self.journal_objects[read_oid][-1]
        except:
            return
        if parameters:
            for x in object_config.copy():
                if x in parameters:
                    continue
                object_config.pop(x)
        return object_config

    def rename_object(self, object_id, new_object_id, **kwargs):
        """ Rename object transaction. """
        from .file import read
        action = "rename"
        if config.debug_level(DEBUG_SLOT) > 4:
            msg = ("Transaction action: %s: %s > %s: %s"
                % (action, object_id, new_object_id, self.log_name))
            logger.debug(msg)
        object_config = self.get_object(object_id)
        if not object_config:
            object_config = read(object_id)
        object_uuid = object_config['UUID']
        # Remove old object data from transaction.
        self.dismiss_object(object_id)
        # Ad new object to transaction.
        self._add_object(new_object_id, object_config)
        # Get spool file.
        journal_file = self.get_journal_file(action)
        # Add journal entry.
        journal_entry = {
                        'action'            : action,
                        'kwargs'            : kwargs,
                        'uuid'              : object_uuid,
                        'old_oid'           : object_id.full_oid,
                        'new_oid'           : new_object_id.full_oid,
                        'journal_file'      : journal_file,
                    }
        self.journal_entries[str(self.journal_counter)] = journal_entry
        self.journal.append(self.journal_counter)
        self.journal_counter += 1

    def delete_object(self, object_id, **kwargs):
        """ Delete object transaction. """
        from .file import read
        action = "delete"
        if config.debug_level(DEBUG_SLOT) > 4:
            msg = ("Transaction action: %s: %s: %s"
                % (action, object_id, self.log_name))
            logger.debug(msg)
        # Get object config of object to be deleted.
        object_config = read(object_id)
        # The object may have been deleted while waiting for the write lock.
        if not object_config:
            return
        # Get spool file.
        journal_file = self.get_journal_file(action)
        # Add journal entry.
        journal_entry = {
                        'action'        : action,
                        'kwargs'        : kwargs,
                        'object_id'     : object_id.full_oid,
                        'object_config' : object_config,
                        'journal_file'  : journal_file,
                    }
        self.journal_entries[str(self.journal_counter)] = journal_entry
        self.journal.append(self.journal_counter)
        self.journal_counter += 1

    def object_exists(self, object_id):
        """ Check if object exists in transaction. """
        action = "exists"
        if config.debug_level(DEBUG_SLOT) > 4:
            msg = ("Transaction action: %s: %s: %s"
                % (action, object_id, self.log_name))
            logger.debug(msg)
        read_oid = object_id.read_oid
        if read_oid in self.journal_objects:
            return True
        return False

    def read_object(self, object_file):
        """ Read object from disk. """
        try:
            object_config_json = filetools.read_file(object_file)
        except Exception as e:
            msg = ("Error reading journal file: %(object_file)s: "
                "%(error)s" % {"object_file":object_file, "error":e})
            logger.critical(msg)
            config.raise_exception()
        # Decode object config.
        object_config = json.loads(object_config_json)
        return object_config

    def _write(self):
        """ Write object transaction to disk. """
        # Will not write empty transaction to disk.
        try:
            self._write_journal()
        except EmptyTransaction:
            return
        if config.debug_level(DEBUG_SLOT) > 3:
            msg = ("Transaction data successful written to disk: %s"
                    % self.log_name)
            logger.debug(msg)
        # Call parent class write method to finalize write.
        return super(ObjectTransaction, self)._write()

    def begin(self):
        """ Start transaction. """
        # Call parent class method.
        super(ObjectTransaction, self).begin()
        # Start nested transaction.
        self.session.begin_nested()

    def commit(self, no_index_writes=True):
        """ Commit write and commit journal. """
        from otpme.lib.backend import outdate_object
        if self.status != "written":
            self._write()
        if config.debug_level(DEBUG_SLOT) > 3:
            msg = ("Commiting transaction: %s" % self.log_name)
            logger.debug(msg)

        # Start commit.
        try:
            added_objects, \
            deleted_objects = self._commit(no_index_writes=no_index_writes)
        except:
            # Rollback DB transaction on error.
            self.session.rollback()
            raise
        else:
            # Commit DB transaction two times because of nested transaction.
            # https://docs.sqlalchemy.org/en/14/orm/session_transaction.html#nested-transaction
            self.session.commit()
            self.session.commit()
        finally:
            # Close DB session.
            self.session.close()

        # Remove status file to indicate finished transaction.
        self._remove_file(self.status_file)

        # Outdate objects in caches.
        for x in deleted_objects:
            cache_type = None
            if self._replay:
                cache_type = "all"
            outdate_object(x, cache_type=cache_type)
        for x in added_objects:
            cache_type = None
            if self._replay:
                cache_type = "all"
            outdate_object(x, cache_type=cache_type)

        if config.debug_level(DEBUG_SLOT) > 3:
            msg = ("Transaction commited successful: %s" % self.log_name)
            logger.debug(msg)

    def _commit(self, no_index_writes=True):
        """ Commit transaction. """
        from .file import write
        from .file import rename
        from .file import delete
        #from otpme.lib.cache import index_cache

        #index_cache.invalidate()

        added_objects = []
        deleted_objects = []
        for x in self.journal:
            commit_files = []
            journal_entry = self.journal_entries[str(x)]
            action = journal_entry['action']
            journal_file = journal_entry['journal_file']
            try:
                kwargs = journal_entry['kwargs']
            except:
                kwargs = {}

            if action == "index_add":
                if not no_index_writes:
                    object_id = journal_entry['object_id']
                    object_id = oid.get(object_id)
                    kwargs = journal_entry['kwargs']
                    self._index_add(object_id, **kwargs)
                    self._remove_file(journal_file)
            elif action == "index_del":
                if not no_index_writes:
                    object_id = journal_entry['object_id']
                    object_id = oid.get(object_id)
                    kwargs = journal_entry['kwargs']
                    self._index_del(object_id, **kwargs)
                    self._remove_file(journal_file)
            elif action == "add":
                object_id = journal_entry['object_id']
                object_config = journal_entry['object_config']
                kwargs = journal_entry['kwargs']
                # Get OID.
                object_id = oid.get(object_id)
                # Add commit files to be removed by file transaction.
                commit_files.append(journal_file)
                if config.debug_level(DEBUG_SLOT) > 0:
                    msg = ("Applying object transaction (write): %s: %s"
                            % (object_id, self.log_name))
                    logger.debug(msg)
                write(object_id, object_config,
                        parent_dir_check=False,
                        commit_files=commit_files,
                        no_index_writes=no_index_writes,
                        transaction_replay=self._replay,
                        **kwargs)
                added_objects.append(object_id)

            if action == "delete":
                object_id = journal_entry['object_id']
                object_config = journal_entry['object_config']
                kwargs = journal_entry['kwargs']
                # Get OID.
                object_id = oid.get(object_id)
                # Add commit files to be removed by file transaction.
                commit_files.append(journal_file)
                if config.debug_level(DEBUG_SLOT) > 0:
                    msg = ("Applying object transaction (delete): %s: %s"
                            % (object_id, self.log_name))
                    logger.debug(msg)
                # At this point object does not exist in index anymore.
                # So we have to pass no_exists_check=True.
                delete(object_id,
                    commit_files=commit_files,
                    no_index_writes=no_index_writes,
                    transaction_replay=self._replay,
                    no_exists_check=True,
                    **kwargs)
                deleted_objects.append(object_id)

            if action == "rename":
                old_oid = journal_entry['old_oid']
                old_oid = oid.get(object_id=old_oid)
                object_uuid = journal_entry['uuid']
                new_oid = journal_entry['new_oid']
                new_oid = oid.get(object_id=new_oid)
                kwargs = journal_entry['kwargs']
                if config.debug_level(DEBUG_SLOT) > 0:
                    msg = ("Applying object transaction (rename): %s > %s: %s"
                            % (old_oid, new_oid, self.log_name))
                    logger.debug(msg)
                # Add commit files to be removed by file transaction.
                commit_files.append(journal_file)
                # Rename object.
                rename(old_oid, new_oid,
                    object_uuid=object_uuid,
                    commit_files=commit_files,
                    transaction_replay=self._replay,
                    no_index_writes=no_index_writes,
                    **kwargs)
                deleted_objects.append(old_oid)

            if action == "add_sign_cache":
                object_id = journal_entry['object_id']
                object_id = oid.get(object_id=object_id)
                user_uuid = journal_entry['user_uuid']
                if config.debug_level(DEBUG_SLOT) > 0:
                    msg = ("Applying object transaction (add sign cache): %s: %s"
                            % (object_id, self.log_name))
                    logger.debug(msg)
                signer_key = self.get_sign_cache(object_id, user_uuid)
                sign_key_cache.add_cache(object_id, signer_key)
                self._remove_file(journal_file)

            if action == "del_sign_cache":
                object_id = journal_entry['object_id']
                object_id = oid.get(object_id=object_id)
                if config.debug_level(DEBUG_SLOT) > 0:
                    msg = ("Applying object transaction (del sign cache): %s: %s"
                            % (object_id, self.log_name))
                    logger.debug(msg)
                try:
                    sign_key_cache.del_cache(object_id)
                except UnknownOID:
                    pass

        return added_objects, deleted_objects

    def replay(self):
        """ Replay transaction. """
        self._replay = True
        # Commit object transaction.
        try:
            result = self.commit(no_index_writes=False)
        finally:
            self._replay = False
        return result

    def remove_file_transactions(self):
        """ Remove related file transactions. """
        for file_transaction in self.file_transactions:
            file_transaction.remove()

    def remove(self):
        """ Delete transaction. """
        self.remove_file_transactions()
        return super(ObjectTransaction, self).remove()
