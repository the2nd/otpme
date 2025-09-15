# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import logging
from functools import wraps

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import syslog
from otpme.lib import config
from otpme.lib import multiprocessing

from otpme.lib.exceptions import *

audit_loggers = {}
logger = config.logger

def audit_log(ignore_args=None, ignore_api_calls=False):
    """ Decorator to handle object lock. """
    def wrapper(f):
        @wraps(f)
        def wrapped(self, *f_args, **f_kwargs):
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
                        msg = "Failed to get audit logger: %s" % e
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
            if result is False:
                if callback:
                    try:
                        job_error = callback.job.exit_info['last_error']
                    except KeyError:
                        job_error = "Unknown error."
                audit_msg = ("[%s] %s: Job failed (%s): %s %s %s %s"
                            % (os.getpid(),
                            auth_token,
                            job_error,
                            func_name,
                            self,
                            log_args,
                            log_kwargs,
                            ))
            else:
                audit_msg = ("[%s] %s: %s %s %s %s"
                            % (os.getpid(),
                            auth_token,
                            func_name,
                            self,
                            log_args,
                            log_kwargs,
                            ))
            audit_logger.info(audit_msg)
            return result
        return wrapped
    return wrapper

def get_audit_logger(address="/dev/log", use_ssl=True, ca_cert_file=None,
    client_cert_file=None, client_key_file=None, relp=False):
    """ Get audit logger. """
    if not config.audit_log_enabled:
        return
    address = config.audit_log_server
    facility = config.audit_log_facility
    relp = False
    if config.audit_log_protocol == "relp":
        relp = True
    ca_cert_file = None
    use_ssl = config.audit_log_use_tls
    if use_ssl:
        client_cert_file = None
        client_key_file = None
        ca_cert_file = config.audit_log_ca_cert
        if not ca_cert_file:
            msg = "Cannot start audit log. Site misses CA cert."
            logger.warning(msg)
            return
        if config.audit_log_use_client_cert:
            client_cert_file = config.audit_log_cert
            client_key_file = config.audit_log_key
            if not client_cert_file:
                msg = "Cannot start audit log. Node misses client cert."
                logger.warning(msg)
                return
            if not client_key_file:
                msg = "Cannot start audit log. Node misses client key."
                logger.warning(msg)
                return
    log_handler = syslog.get_log_handler(address=address,
                                        use_ssl=use_ssl,
                                        ca_cert_file=ca_cert_file,
                                        client_cert_file=client_cert_file,
                                        client_key_file=client_key_file,
                                        facility=facility,
                                        relp=relp)
    audit_logger = logging.getLogger('OTPme-audit')
    audit_logger.setLevel(logging.DEBUG)
    if audit_logger.hasHandlers():
        audit_logger.handlers.clear()
    audit_logger.addHandler(log_handler)
    return audit_logger
