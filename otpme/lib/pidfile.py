# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
from functools import wraps

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import filetools

from otpme.lib.exceptions import *

def pidfile_handler(pidfile):
    """ Decorator to handle pidfile. """
    def wrapper(func):
        @wraps(func)
        def wrapped(*args, **kwargs):
            # Check for running process via PIDFILE.
            pid = is_running(pidfile)
            if pid:
                msg = "nsscache already running with PID: %s" % pid
                raise AlreadyRunning(msg)
            # Create PIDFILE.
            create_pidfile(pidfile)
            # Run function.
            try:
                result = func(*args, **kwargs)
            except:
                raise
            finally:
                # Remove PIDFILE.
                os.remove(pidfile)
            return result
        return wrapped
    return wrapper


def is_running(pidfile):
    if not os.path.exists(pidfile):
        return False
    # Get logger.
    logger = config.logger
    try:
        nsscache_pid = filetools.read_file(pidfile)
    except Exception as e:
        msg = "Failed to read pidfile: %s" % e
        logger.warning(msg)
        return True
    if stuff.check_pid(nsscache_pid):
        return nsscache_pid
    msg = "Removing stale pidfile: %s" % pidfile
    logger.warning(msg)
    try:
        filetools.delete(pidfile)
    except Exception as e:
        msg = "Failed to remove stale pidfile: %s" % e
        logger.warning(msg)
    return False

def create_pidfile(pidfile):
    pid = os.getpid()
    # Get logger.
    logger = config.logger
    try:
        filetools.create_file(path=pidfile, content=str(pid))
    except Exception as e:
        msg = "Failed to create pidfile: %s" % e
        logger.warning(msg)

