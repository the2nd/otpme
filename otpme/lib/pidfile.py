# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import fcntl
from functools import wraps

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {__name__}")
        msg = msg.format(__name__=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import config
from otpme.lib import filetools

from otpme.lib.exceptions import *

# The open file descriptions that hold a pidfile, by path. Each one
# carries an exclusive flock, and that is what says whether somebody is
# working: the kernel gives a flock back when the process dies, however
# it dies. The pid in the file cannot say it. A process that is killed,
# or that leaves through the SIGTERM handler of a daemon child
# (multiprocessing.signal_handler, os._exit), never runs the finally
# that removes the file -- and the pid it left behind is either dead, or
# worse, handed out again to somebody else, which used to read as "still
# running" for as long as that process lived.
#
# A process that forks while it holds one hands the child the same open
# file description, so the child holds the very same lock. That is why a
# child must not give it back: closing it there would take the lock away
# from the parent that is still working.
held_pidfiles = {}


def pidfile_handler(pidfile, proc_name="Process"):
    """ Decorator to handle pidfile. """
    def wrapper(func):
        @wraps(func)
        def wrapped(*args, **kwargs):
            # Takes the pidfile and says who has it, see hold_pidfile().
            create_pidfile(pidfile, proc_name=proc_name)
            # Run function.
            try:
                result = func(*args, **kwargs)
            except Exception:
                raise
            finally:
                # Remove PIDFILE.
                remove_pidfile(pidfile)
            return result
        return wrapped
    return wrapper


def hold_pidfile(pidfile, proc_name="Process"):
    """ Take the pidfile of this process, or say who holds it.

    Raises AlreadyRunning where somebody else is in it.

    The file is opened without truncating it, so the pid of whoever
    holds it can still be read and put in the message.
    """
    logger = config.logger
    if pidfile in held_pidfiles:
        # Held by this process already. Says the same thing as a lock
        # taken twice would, and without taking the lock away from the
        # work that is running.
        msg = _("{proc_name} already running with PID: {pid}")
        msg = msg.format(proc_name=proc_name, pid=os.getpid())
        raise AlreadyRunning(msg)
    try:
        fd = open(pidfile, "a+")
    except Exception as e:
        log_msg = _("Failed to open pidfile: {e}", log=True)[1]
        log_msg = log_msg.format(e=e)
        logger.warning(log_msg)
        return None
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (OSError, IOError):
        try:
            fd.seek(0)
            pid = fd.read().strip() or "unknown"
        except Exception:
            pid = "unknown"
        fd.close()
        msg = _("{proc_name} already running with PID: {pid}")
        msg = msg.format(proc_name=proc_name, pid=pid)
        raise AlreadyRunning(msg) from None
    held_pidfiles[pidfile] = fd
    return fd


def release_pidfile(pidfile):
    """ Give the pidfile back, and with it its lock. """
    fd = held_pidfiles.pop(pidfile, None)
    if fd is None:
        return
    try:
        fd.close()
    except Exception:
        pass


def remove_pidfile(pidfile):
    """ Remove the pidfile of this process. """
    logger = config.logger
    release_pidfile(pidfile)
    try:
        os.remove(pidfile)
    except FileNotFoundError:
        pass
    except Exception as e:
        log_msg = _("Failed to remove pidfile: {e}", log=True)[1]
        log_msg = log_msg.format(e=e)
        logger.warning(log_msg)


def read_pidfile(pidfile):
    """ The pid in the file, and whether somebody holds the file.

    Both off one open file descriptor, and with a plain open(): a
    pidfile must not be read through filetools, which takes a read lock
    of its own and would wait for the exclusive one of whoever is
    working.

    Whether somebody is working is asked of the lock and not of the pid,
    see held_pidfiles. A file that cannot be opened counts as held --
    not being able to look is no reason to start a second one.
    """
    if pidfile in held_pidfiles:
        return str(os.getpid()), True
    try:
        fd = open(pidfile, "rb")
    except FileNotFoundError:
        return None, False
    except Exception as e:
        logger = config.logger
        log_msg = _("Failed to open pidfile: {e}", log=True)[1]
        log_msg = log_msg.format(e=e)
        logger.warning(log_msg)
        return None, True
    try:
        try:
            pid = fd.read().decode().strip()
        except Exception as e:
            logger = config.logger
            log_msg = _("Failed to read pidfile: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            logger.warning(log_msg)
            return None, True
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, IOError):
            return pid, True
        # Taken only to ask. The close in the finally gives it back --
        # a flock goes with the open file description it was taken on --
        # and it has to, or the next one would find it held and believe
        # somebody is working.
        return pid, False
    finally:
        fd.close()


def is_running(pidfile, quiet=False):
    """ Whether the process this pidfile is for is working.

    The pid it holds where it is, False where it is not.
    """
    # Get logger.
    logger = config.logger
    pid, working = read_pidfile(pidfile)
    if working:
        return pid or True
    if pid is None:
        return False
    # A file nobody holds. The process it was for is gone, and a pid
    # that is alive here is one that was handed out again -- which used
    # to read as "still running" and held off every later run.
    #
    # Said at debug level and not as a warning: a process that is killed
    # cannot take its pidfile with it, so a leftover is bookkeeping and
    # not something that went wrong. The ones that end by themselves
    # remove it (remove_pidfile).
    if not quiet:
        log_msg = _("Removing pidfile of a process that is gone: {pidfile} ({pid})", log=True)[1]
        log_msg = log_msg.format(pidfile=pidfile, pid=pid)
        logger.debug(log_msg)
    try:
        filetools.delete(pidfile)
    except FileNotFoundError:
        pass
    except Exception as e:
        log_msg = _("Failed to remove stale pidfile: {e}", log=True)[1]
        log_msg = log_msg.format(e=e)
        logger.warning(log_msg)
    return False

def create_pidfile(pidfile, proc_name="Process"):
    """ Take the pidfile and write our pid into it.

    Raises AlreadyRunning where somebody else holds it. Taking it and
    writing it are one step, so two processes cannot both find that
    nobody is in it: asking first and writing after leaves a window
    between the two.
    """
    pid = os.getpid()
    # Get logger.
    logger = config.logger
    if not os.path.exists(pidfile):
        # Only where there is none. The one that is there belongs to
        # somebody else until the lock below says otherwise:
        # create_file() would write over the pid in it, and it takes a
        # lock of its own on the way, so it would sit and wait for
        # whoever is working to finish.
        try:
            filetools.create_file(path=pidfile, content="", lock=False)
        except Exception as e:
            log_msg = _("Failed to create pidfile: {e}", log=True)[1]
            log_msg = log_msg.format(e=e)
            logger.warning(log_msg)
    fd = hold_pidfile(pidfile, proc_name=proc_name)
    if fd is None:
        return
    try:
        fd.seek(0)
        fd.truncate()
        fd.write(str(pid))
        fd.flush()
    except Exception as e:
        log_msg = _("Failed to write pidfile: {e}", log=True)[1]
        log_msg = log_msg.format(e=e)
        logger.warning(log_msg)

