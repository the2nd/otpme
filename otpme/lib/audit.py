# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import json
import time
import socket
import logging
from functools import wraps

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except:
    pass

from otpme.lib import config
from otpme.lib import syslog
from otpme.lib import filetools
from otpme.lib import multiprocessing
from otpme.lib.multiprocessing import register_atfork_method

from otpme.lib.exceptions import *

audit_loggers = {}

def atfork_cleanup():
    global audit_loggers
    audit_loggers.clear()
register_atfork_method(atfork_cleanup)

def audit_log(ignore_args=None, ignore_api_calls=False):
    """ Decorator to handle object lock. """
    def wrapper(f):
        @wraps(f)
        def wrapped(self, *f_args, **f_kwargs):
            logger = config.logger
            global audit_loggers
            _ignore_args = [
                            'verbose_level',
                            'force',
                            'callback',
                            '_caller',
                            'lock_timeout',
                            'run_policies',
                            'lock_reload_on_change',
                            ]
            try:
                callback = f_kwargs['callback']
            except KeyError:
                callback = None
            try:
                no_audit_log = f_kwargs['no_audit_log']
            except KeyError:
                no_audit_log = False
            if not no_audit_log:
                proc_id = multiprocessing.get_id()
                try:
                    audit_logger = audit_loggers[proc_id]
                except KeyError:
                    audit_logger = None

                # Dont do audit log on realm init.
                if audit_logger is None and not config.realm_init:
                    # Get audit logger.
                    try:
                        audit_logger = get_audit_logger()
                    except Exception as e:
                        msg = _("Failed to get audit logger: {error}")
                        msg = msg.format(error=e)
                        logger.warning(msg)
                        audit_logger = None
                    else:
                        audit_loggers[proc_id] = audit_logger
            # Call given class method.
            try:
                result = f(self, *f_args, **f_kwargs)
            except:
                raise

            if no_audit_log:
                return result

            if not audit_logger:
                return result

            func_name = f.__name__
            log_args = list(f_args)
            log_kwargs = dict(f_kwargs)
            if ignore_args is not None:
                for kwarg in ignore_args:
                    try:
                        log_kwargs.pop(kwarg)
                    except KeyError:
                        pass
            for kwarg in _ignore_args:
                try:
                    log_kwargs.pop(kwarg)
                except KeyError:
                    pass
            if config.auth_token:
                auth_token = config.auth_token.rel_path
            else:
                if ignore_api_calls:
                    return result
                auth_token = "API"

            if callback:
                job_client = callback.job.client
                try:
                    job_error = callback.job.exit_info['last_error']
                except KeyError:
                    pass
            else:
                job_client = "Unknown client"
                job_error = "Unknown error"

            if result is False:
                audit_msg = _("[{pid}] Client: {client}: Token: {token}: Job failed ({error}): Data: {func} {self} {args} {kwargs}")
                audit_msg = audit_msg.format(pid=os.getpid(), client=job_client, token=auth_token, error=job_error, func=func_name, self=self, args=log_args, kwargs=log_kwargs)
            else:
                audit_msg = _("[{pid}] Client: {client}: Token: {token}: Data: {func} {self} {args} {kwargs}")
                audit_msg = audit_msg.format(pid=os.getpid(), client=job_client, token=auth_token, func=func_name, self=self, args=log_args, kwargs=log_kwargs)
            audit_logger.info(audit_msg)
            return result
        return wrapped
    return wrapper

def spool_record(record):
    import pwd
    import grp
    from otpme.lib import config
    logger = config.logger
    spool_dir = config.audit_log_spool_dir
    if not os.path.exists(spool_dir):
        return
    record_data = {
                    'created'   : record.created,
                    'loglevel'  : record.levelname,
                    'message'   : record.msg,
                }
    record_data = json.dumps(record_data)
    record_data = record_data.encode()
    while True:
        spool_file = os.path.join(spool_dir, str(time.time_ns()))
        try:
            fd = os.open(spool_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.write(fd, record_data)
            os.close(fd)
        except FileExistsError:
            continue
        except Exception as e:
            msg = _("Failed to create audit log spool file: {file}: {error}")
            msg = msg.format(file=spool_file, error=e)
            logger.warning(msg)
            return
        break
    # Set ownership.
    uid = pwd.getpwnam(config.user).pw_uid
    gid = grp.getgrnam(config.group).gr_gid
    os.chown(spool_file, uid, gid)

def process_spooled_logs():
    logger = config.logger
    spool_dir = config.audit_log_spool_dir
    if not os.path.exists(spool_dir):
        return
    try:
        spool_files = os.listdir(spool_dir)
    except Exception as e:
        msg = _("Failed to read spool dir: {dir}: {error}")
        msg = msg.format(dir=spool_dir, error=e)
        logger.warning(msg)
        return
    if not spool_files:
        return
    try:
        audit_logger = get_audit_logger(no_spool=True, exception_on_emit=True)
    except Exception as e:
        msg = _("Failed to get audit logger: {error}")
        msg = msg.format(error=e)
        logger.warning(msg)
        return
    for x in spool_files:
        spool_file = os.path.join(spool_dir, x)
        try:
            spool_data = filetools.read_file(spool_file)
        except Exception as e:
            msg = _("Failed to read log spool file: {error}")
            msg = msg.format(error=e)
            logger.warning(msg)
            continue
        try:
            spool_data = json.loads(spool_data)
        except Exception as e:
            msg = _("Failed to load log spool data: {file}: {error}")
            msg = msg.format(file=spool_file, error=e)
            logger.warning(msg)
            continue
        try:
            timestamp = spool_data['created']
            loglevel = spool_data['loglevel']
            message = spool_data['message']
        except KeyError:
            msg = _("Got invalid log entry: {file}")
            msg = msg.format(file=spool_file)
            logger.warning(msg)
            continue
        log_message = _("LOG_RESEND: {timestamp}: {message}")
        log_message = log_message.format(timestamp=timestamp, message=message)
        try:
            log_method = getattr(audit_logger, loglevel.lower())
        except:
            msg = _("Invalid loglevel: {level}: {file}")
            msg = msg.format(level=loglevel, file=spool_file)
            logger.warning(msg)
            continue
        try:
            log_method(log_message)
        except Exception as e:
            msg = _("Failed to resend log message: {error}")
            msg = msg.format(error=e)
            logger.warning(msg)
            if isinstance(e, socket.error):
                break
            continue
        try:
            os.remove(spool_file)
        except Exception as e:
            msg = _("Failed to remove spool file: {file}: {error}")
            msg = msg.format(file=spool_file, error=e)
            logger.warning(msg)

    for handler in audit_logger.handlers:
        try:
            handler.close()
        except:
            pass

def get_audit_logger(no_spool=False, exception_on_emit=False):
    """ Get audit logger. """
    if not config.audit_log_enabled:
        return
    if not config.audit_log_server:
        return
    logger = config.logger
    address = config.audit_log_server
    facility = config.audit_log_facility
    relp = False
    if config.audit_log_protocol == "relp":
        relp = True
    ca_cert_file = None
    ca_cert_file = None
    client_key_file = None
    client_cert_file = None
    use_ssl = config.audit_log_use_tls
    if no_spool:
        spool_method = None
    else:
        spool_method = spool_record
    if use_ssl:
        ca_cert_file = config.audit_log_ca_cert
        if not ca_cert_file:
            msg = _("Cannot start audit log. Site misses CA cert.")
            logger.warning(msg)
            return
        if config.audit_log_use_client_cert:
            client_cert_file = config.audit_log_cert
            client_key_file = config.audit_log_key
            if not client_cert_file:
                msg = _("Cannot start audit log. Node misses client cert.")
                logger.warning(msg)
                return
            if not client_key_file:
                msg = _("Cannot start audit log. Node misses client key.")
                logger.warning(msg)
                return
    log_handler = syslog.get_log_handler(address=address,
                                        use_ssl=use_ssl,
                                        ca_cert_file=ca_cert_file,
                                        client_cert_file=client_cert_file,
                                        client_key_file=client_key_file,
                                        facility=facility,
                                        relp=relp,
                                        spool_method=spool_method,
                                        exception_on_emit=exception_on_emit)
    audit_logger = logging.getLogger('OTPme-audit')
    audit_logger.setLevel(logging.DEBUG)
    if audit_logger.hasHandlers():
        audit_logger.handlers.clear()
    audit_logger.addHandler(log_handler)
    return audit_logger
