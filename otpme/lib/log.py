# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import sys
import time
import logging
# We need this import to get access to logging.handlers.
import logging.config
from functools import wraps

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {}")
        msg = msg.format(__name__)
        print(msg)
except:
    pass

from otpme.lib.syslog import get_log_handler
from otpme.lib.filetools import AtomicFileLock

fd = None
LOCK_TYPE = "log"
log_banner = None

# Prevent "Broken Pipe" messages when piping daemon output e.g. to tee(1)
logging.raiseExceptions = False

# List with valid loglevels
valid_log_levels = [ "CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG" ]

def atfork():
    """ Blank any FD from parent process. """
    global fd
    fd = None

# We need this to add variables to logging format.
class ContextFilter(logging.Filter):
    """ Add log banner and filter log messages. """
    def filter(self, record):
        from otpme.lib import config
        global log_banner
        valid_log = True
        record.log_banner = log_banner
        if config.log_filter:
            valid_log = False
            for x in config.log_filter:
                x_check = f"{config.my_name.lower()}-{x}"
                if log_banner and log_banner.startswith(x_check):
                    valid_log = True
                    break
        return valid_log

def get_logger(log_name, level, syslog=False, syslog_address="/dev/log",
    syslog_ssl=False, syslog_ca_cert=None, syslog_cert=None, syslog_key=None,
    syslog_relp=False, logger=None, pid=None, banner=None, logfile=None,
    facility="LOCAL7", systemd=False, timestamps=None, color_logs=False,
    stderr_log=False):
    """ Get new logger instance or re-configure a given one """
    global log_banner
    unknown_loglevel = None

    # Make log name lowercase.
    log_name = log_name.lower()

    # Handle colored logs.
    log_formatter = logging.Formatter
    if color_logs:
        from colorlog import ColoredFormatter
        log_formatter = ColoredFormatter

    # Catch unknown loglevels
    if level not in valid_log_levels:
        unknown_loglevel = level
        level = "INFO"

    # Get PID if needed.
    if pid is True:
        pid = os.getpid()

    # Use given banner or set one.
    if banner is True:
        log_banner = log_name
    elif isinstance(banner, str):
        log_banner = banner
    elif logger:
        log_banner = logger.banner
    else:
        log_banner = None

    if log_banner:
        # Add PID to banner if given.
        if pid and not syslog:
            log_banner = f"{log_banner}[{pid}]"

        # Add colon to banner.
        log_banner = f"{log_banner}:"

        # Logformat without date.
        LOG_FORMAT = '%(log_banner)s %(levelname)s: %(message)s'
        # Logformat with date.
        LOG_FORMAT_DATE = '%(asctime)s %(log_banner)s %(levelname)s: %(message)s'
    else:
        # Logformat without date.
        LOG_FORMAT = '%(levelname)s: %(message)s'
        # Logformat with date.
        LOG_FORMAT_DATE = '%(asctime)s %(levelname)s: %(message)s'

    # Add colors to log.
    if color_logs:
        LOG_FORMAT = '%(log_color)s' + LOG_FORMAT + '%(reset)s'
        LOG_FORMAT_DATE = '%(log_color)s' + LOG_FORMAT_DATE + '%(reset)s'

    # Add log formatters.
    log_format_date = log_formatter(LOG_FORMAT_DATE, datefmt='%Y-%m-%d %H:%M:%S')
    log_format_without_date = log_formatter(LOG_FORMAT)

    if timestamps is True:
        log_format = log_format_date
    elif timestamps is False:
        log_format = log_format_without_date
    else:
        log_format = None

    # Create new logger if there where no logger instance given to us.
    if not logger:
        logger = logging.getLogger(log_name)

    if logger.hasHandlers():
        logger.handlers.clear()

    # Add filter to add log_banner to format string of logging.
    logger.addFilter(ContextFilter())

    # Set loglevel.
    logger.setLevel(level)

    # Check if we should log to syslog.
    if syslog:
        # Default log format should be with date.
        if not log_format:
            log_format = log_format_date
        # Create syslog handler:
        syslog_handler = get_log_handler(address=syslog_address,
                                        use_ssl=syslog_ssl,
                                        ca_cert_file=syslog_ca_cert,
                                        client_cert_file=syslog_cert,
                                        client_key_file=syslog_key,
                                        facility=facility,
                                        relp=syslog_relp)
        # Set log format for handler
        syslog_handler.setFormatter(log_format)
        # If file logging is not enabled print to stdout.
        logger.addHandler(syslog_handler)
    # Check if we should log to file.
    elif logfile:
        # Default log format should be with date.
        if not log_format:
            log_format = log_format_date
        # Create handler for logfile.
        file_handler = logging.handlers.WatchedFileHandler(logfile,)
        # Set log format for handler.
        file_handler.setFormatter(log_format)
        # Enable logging to logfile.
        logger.addHandler(file_handler)

    elif systemd:
        from systemd import journal
        # Get journald handler.
        journald_handler = journal.JournaldLogHandler()

        # Set log journald format for handler:
        log_format = log_formatter('%(levelname)s: %(message)s')
        journald_handler.setFormatter(log_format)

        # Add journald handler.
        logger.addHandler(journald_handler)
    else:
        # Default log format should be without date.
        if not log_format:
            log_format = log_format_without_date
        # Create handler for stdout.
        if stderr_log:
            stdout_handler = logging.StreamHandler(stream=sys.stderr)
        else:
            stdout_handler = logging.StreamHandler(stream=sys.stdout)
        # Set log format for handler.
        stdout_handler.setFormatter(log_format)
        # If file logging is not enabled print to stdout.
        logger.addHandler(stdout_handler)

    if unknown_loglevel:
        msg = _("Changed unknown loglevel '{}' to loglevel 'INFO'.")
        msg = msg.format(unknown_loglevel)
        logger.error(msg)

    otpme_logger = OTPmeLogger(logger, logfile=logfile, banner=log_banner)

    return otpme_logger

def setup_logger(*args, **kwargs):
    """ Configure logger based on site settings. """
    from otpme.lib import config
    relp = False
    use_ssl = False
    ca_cert_file = None
    client_cert_file = None
    client_key_file = None
    address = None
    timestamps = True
    logger_syslog = False
    if not config.debug_enabled and not config.realm_init:
        if config.syslog_enabled and config.syslog_server:
            logger_syslog = True
            timestamps = False
            address = config.syslog_server
            relp = False
            if config.syslog_protocol == "relp":
                relp = True
            use_ssl = config.syslog_use_tls
            if use_ssl:
                ca_cert_file = config.syslog_ca_cert
                if not ca_cert_file:
                    logger_syslog = False
                    msg = _("Cannot start syslog. Site misses CA cert.")
                    config.logger.warning(msg)
                if config.syslog_use_client_cert:
                    client_cert_file = config.syslog_cert
                    client_key_file = config.syslog_key
                    if not client_cert_file:
                        logger_syslog = False
                        msg = _("Cannot start syslog. Node misses client cert.")
                        config.logger.warning(msg)
                    if not client_key_file:
                        logger_syslog = False
                        msg = _("Cannot start syslog. Node misses client key.")
                        config.logger.warning(msg)
    # Setup logger.
    logger = config.setup_logger(*args,
                                logger_syslog=logger_syslog,
                                syslog_address=address,
                                syslog_ssl=use_ssl,
                                syslog_ca_cert=ca_cert_file,
                                syslog_cert=client_cert_file,
                                syslog_key=client_key_file,
                                syslog_relp=relp,
                                timestamps=timestamps,
                                **kwargs)
    return logger

def log_lock():
    """ Decorator to handle logfile locking. """
    # https://docs.python.org/dev/howto/logging-cookbook.html#logging-to-a-single-file-from-multiple-processes
    def wrapper(f):
        @wraps(f)
        def wrapped(self, *f_args, **f_kwargs):
            global fd
            if self.logfile:
                from otpme.lib import config
                if fd:
                    try:
                        fd.release_lock()
                    except:
                        pass
                    try:
                        fd.close()
                    except:
                        pass
                    fd = None
                if config.locks_dir:
                    counter = 0
                    max_wait = 1000
                    lock_id = self.logfile.replace("/", ":")
                    lock_file = (f"{config.locks_dir}/{lock_id}")
                    while counter < max_wait:
                        try:
                            fd = AtomicFileLock(path=lock_file,
                                                user=config.user,
                                                group=config.group,
                                                write_lock=True,
                                                block=False)
                            break
                        except IOError:
                            counter += 1
                            time.sleep(0.001)
                    if not fd:
                        msg = _("Failed to acquire logfile lock: {}\n")
                        msg = msg.format(self.logfile)
                        sys.stderr.write(msg)
                        sys.stderr.flush()
            # Call given class method.
            try:
                result = f(self, *f_args, **f_kwargs)
            finally:
                # Make sure we release lock.
                if self.logfile:
                    if fd:
                        try:
                            fd.release_lock()
                        except:
                            pass
                        try:
                            fd.close()
                        except:
                            pass
                        try:
                            fd.unlink()
                        except:
                            pass
                        fd = None
            return result
        return wrapped
    return wrapper

class OTPmeLogger(object):
    """ Wrapper class to handle logfile locking. """
    def __init__(self, logger, logfile=None, banner=None):
        self.logger = logger
        self.logfile = logfile
        self.banner = banner

    def __getattr__(self, name):
        """ Map to original logger attributes. """
        return getattr(self.logger, name)

    def atfork(self):
        for h in self.handlers:
             self.removeHandler(h)

    @log_lock()
    def debug(self, *args, **kwargs):
        return self.logger.debug(*args, **kwargs)

    @log_lock()
    def info(self, *args, **kwargs):
        return self.logger.info(*args, **kwargs)

    @log_lock()
    def warning(self, *args, **kwargs):
        #kwargs['exc_info'] = True
        return self.logger.warning(*args, **kwargs)

    @log_lock()
    def error(self, *args, **kwargs):
        #kwargs['exc_info'] = True
        return self.logger.error(*args, **kwargs)

    @log_lock()
    def critical(self, *args, **kwargs):
        #kwargs['exc_info'] = True
        return self.logger.critical(*args, **kwargs)

    @log_lock()
    def warn(self, *args, **kwargs):
        return self.logger.warn(*args, **kwargs)

    @log_lock()
    def fatal(self, *args, **kwargs):
        return self.logger.fatal(*args, **kwargs)
