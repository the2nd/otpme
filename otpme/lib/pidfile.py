# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
from functools import wraps

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {__name__}")
        msg = msg.format(__name__=__name__)
        print(msg)
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
                msg = _("nsscache already running with PID: {pid}")
                msg = msg.format(pid=pid)
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
        log_msg = _("Failed to read pidfile: {e}", log=True)[1]
        log_msg = log_msg.format(e=e)
        logger.warning(log_msg)
        return True
    if stuff.check_pid(nsscache_pid):
        return nsscache_pid
    log_msg = _("Removing stale pidfile: {pidfile}", log=True)[1]
    log_msg = log_msg.format(pidfile=pidfile)
    logger.warning(log_msg)
    try:
        filetools.delete(pidfile)
    except Exception as e:
        log_msg = _("Failed to remove stale pidfile: {e}", log=True)[1]
        log_msg = log_msg.format(e=e)
        logger.warning(log_msg)
    return False

def create_pidfile(pidfile):
    pid = os.getpid()
    # Get logger.
    logger = config.logger
    try:
        filetools.create_file(path=pidfile, content=str(pid))
    except Exception as e:
        log_msg = _("Failed to create pidfile: {e}", log=True)[1]
        log_msg = log_msg.format(e=e)
        logger.warning(log_msg)

