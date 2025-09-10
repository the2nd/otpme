# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import sys
import time
import signal
import pprint
import hashlib
import datetime
import threading
import setproctitle

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import re
from otpme.lib import oid
from otpme.lib import json
from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import backup
from otpme.lib import backend
from otpme.lib import encryption
from otpme.lib import jwt as _jwt
from otpme.lib.humanize import units
from otpme.lib import multiprocessing
from otpme.lib.encoding.base import decode
from otpme.lib.encryption.rsa import RSAKey
from otpme.lib.protocols import status_codes
from otpme.lib.job.otpme_job import OTPmeJob
from otpme.lib.protocols.utils import send_msg
from otpme.lib.protocols.otpme_server import OTPmeServer1

from otpme.lib.exceptions import *

logger = config.logger
default_callback = config.get_callback()

sub_types = {}
command_map = {}

# All valid commands
valid_commands = [
                'trash',
                'backend',
                'stop_job',
                'move_object',
                'mass_object_add',
                'change_user_default_group',
                'dump_index',
                'dump_object',
                'reset_reauth',
                'delete_object',
                'get_share',
                'get_shares',
                'get_token_type',
                'get_policy_type',
                'check_duplicate_ids',
                ]

REGISTER_BEFORE = []
REGISTER_AFTER = [
                'otpme.lib.classes.realm',
                'otpme.lib.protocols.otpme_server',
                'otpme.lib.classes.data_objects.data_revision',
                ]

PROTOCOL_VERSION = "OTPme-mgmt-1.0"

def register():
    config.register_otpme_protocol("mgmtd", PROTOCOL_VERSION, server=True)

class OTPmeMgmtP1(OTPmeServer1):
    """ Class that implements OTPme-mgmt-1.0 """
    def __init__(self, **kwargs):
        # Our name
        self.name = "mgmtd"
        # The protocol we support
        self.protocol = PROTOCOL_VERSION
        # Indicates parent class that we need an authenticated user.
        self.require_auth = "user"
        self.require_preauth = True
        # The accessgroup we authenticate users against.
        self.access_group = config.mgmt_access_group
        # Indicates parent class to require a client certificate.
        self.require_client_cert = True
        # Will hold all running jobs
        self.jobs = {}
        self.running_jobs = {}
        self.job_queries = {}
        self.job_exit_status = {}
        self.job_callbacks = {}
        # Max jobs per client.
        self.max_jobs = 3
        # Mass add procs.
        self.mass_add_procs = {}
        # Our PID.
        self.pid = None
        # Event to handle jobs.
        self.new_job_event = None
        self.new_query_event = None
        # Management server requires master node.
        self.require_master_node = True
        # call parent class init
        OTPmeServer1.__init__(self, **kwargs)

    def _pre_init(self, *args, **kwargs):
        """ Init protocol handler. """
        # Our PID.
        self.pid = os.getpid()
        # Set signal handler.
        signal.signal(signal.SIGTERM, self.signal_handler)
        signal.signal(signal.SIGINT, self.signal_handler)
        # Event to handle jobs.
        self.new_job_event = threading.Event()
        self.new_query_event = threading.Event()
        # Start thread to handle jobs.
        multiprocessing.start_thread(name=self.name,
                                    target=self.handle_jobs,
                                    daemon=True)

    def signal_handler(self, _signal, frame):
        """ Exit on signal. """
        if _signal != 15:
            return
        # Act only on our own PID.
        if os.getpid() != self.pid:
            return
        msg = ("Received SIGTERM.")
        self.logger.info(msg)

        for job_uuid in dict(self.jobs):
            job = self.jobs[job_uuid]
            if not job.start_process:
                try:
                    self.jobs.pop(job_uuid)
                except KeyError:
                    pass
                job.close()
                continue
            if not job.is_alive():
                continue
            # Sent stop signal to job.
            job.stop(signal=15)
        while True:
            jobs_stopped = True
            for job_uuid in dict(self.jobs):
                if not job.is_alive():
                    try:
                        self.jobs.pop(job_uuid)
                    except KeyError:
                        pass
                    job.close()
                    continue
                jobs_stopped = False
                time.sleep(0.01)
            if jobs_stopped:
                break
        self._close()
        # Call parent class protocol handler.
        super(OTPmeMgmtP1, self).signal_handler(_signal, frame)
        # Using sys.exit() may result in hanging process.
        os._exit(0)

    def handle_jobs(self):
        """ Handle job queries when in daemon mode. """
        while True:
            if len(self.running_jobs) == 0:
                # Wait for wakeup by new job.
                if self.new_job_event:
                    self.new_job_event.wait()
                    self.new_job_event.clear()
            # Handle job queries.
            for job_uuid in dict(self.running_jobs):
                self._handle_job_queries(job_uuid)

    def _handle_job_queries(self, job_uuid, timeout=0.1):
        """ Receive job messages and join job process on exit. """
        try:
            job = self.running_jobs[job_uuid]
        except:
            return
        # Get comm handler to communicate with job.
        job_comm_handler = job.comm_queue.get_handler("client")
        # Get message/query from job.
        try:
            sender, \
            command, \
            callback_query = job_comm_handler.recv(timeout=timeout)
        except TimeoutReached:
            command = None
        except QueueClosed:
            command = None
        except ExitOnSignal:
            command = None
        if command and command != "job_end":
            try:
                job_queries = self.job_queries[job_uuid]
            except:
                job_queries = []
                self.job_queries[job_uuid] = job_queries
            query = {'command':command, 'query':callback_query}
            job_queries.append(query)
            if self.new_query_event:
                self.new_query_event.set()
            return True
        if job.is_alive():
            return True
        # Check if we got a termination message that should be printed.
        if job.term_message:
            exit_message = job.term_message
        else:
            # If not try to get job exit message.
            try:
                exit_message = job.exit_info['exit_message']
            except KeyError:
                exit_message = ""
        # Get job exit code.
        try:
            exit_status = job.exit_info['exit_status']
        except KeyError:
            exit_status = False
        self.job_exit_status[job_uuid] = {}
        self.job_exit_status[job_uuid]['exit_status'] = exit_status
        self.job_exit_status[job_uuid]['exit_message'] = exit_message
        self.job_exit_status[job_uuid]['objects_written'] = job.objects_written.value
        # Close job.
        job.close()
        if self.new_query_event:
            self.new_query_event.set()
        if not config.use_api:
            try:
                multiprocessing.running_jobs.pop(job_uuid)
            except KeyError:
                pass
        try:
            self.running_jobs.pop(job_uuid)
        except KeyError:
            pass

    def get_method_args(self, command_args, args, _args, opt_args, _opt_args, _dargs):
        """ Return requested args from command_args + global args """
        _method_args = {}
        # Method arguments that will be passed to all methods (if present)
        global_args = [ 'force', 'verbose_level' ]
        # API callers that are allowed from remote. Class methods use them to
        # decide e.g. which format the return value must have.
        api_callers = [ 'CLIENT', 'RAPI' ]

        # Get global method args.
        for a in global_args:
            try:
                _method_args[a] = command_args.pop(a)
            except:
                pass

        # Get mandatory args.
        for a in _args:
            if a in global_args:
                continue
            try:
                _method_args[a] = command_args.pop(a)
            except KeyError:
                try:
                    _method_args[a] = args[a]
                except KeyError:
                    try:
                        _method_args[a] = _dargs[a]
                    except KeyError:
                        # If args and command_args misses a required arg the
                        # command is incomplete.
                        msg = "Missing required argument: %s" % a
                        raise OTPmeException(msg)

        # Get optional args.
        for a in _opt_args:
            if a in global_args:
                continue
            if a in args:
                continue
            try:
                _method_args[a] = command_args.pop(a)
            except KeyError:
                try:
                    _method_args[a] = opt_args[a]
                except KeyError:
                    try:
                        _method_args[a] = _dargs[a]
                    except KeyError:
                        pass

        for a in _dargs:
            if a in _method_args:
                continue
            _method_args[a] = _dargs[a]

        # Make sure we pass only allowed API callers.
        try:
            _caller = command_args['_caller']
        except:
            _caller = "CLIENT"

        if _caller not in api_callers:
            logger.warning("Request contains invalid API caller: %s" % _caller)
            _caller = "CLIENT"

        _method_args['_caller'] = _caller

        return _method_args

    def start_job(self, name, target_method, args={}, _args={}, opt_args={},
        _opt_args={}, _dargs={}, command_args={}, thread=True, process=False):
        """ Start command as child process. """
        if len(self.running_jobs) >= self.max_jobs:
            job_reply = "Max jobs reached (%s)" % self.max_jobs
            return False, job_reply
        # Get method args from command_args
        _method_args = self.get_method_args(command_args, args, _args, opt_args, _opt_args, _dargs)
        _caller = _method_args['_caller']

        # Get timeout arg.
        try:
            job_timeout = command_args['job_timeout']
        except:
            job_status = False
            job_reply = "Job request missing timeout parameter: %s" % name
            return job_status, job_reply
        # Get lock args.
        try:
            lock_timeout = command_args['lock_timeout']
            lock_wait_timeout = command_args['lock_wait_timeout']
        except:
            job_status = False
            job_reply = "Job request missing lock parameters."
            return job_status, job_reply
        # Get object auto-reload arg.
        try:
            reload_on_change = command_args['lock_reload_on_change']
        except:
            job_status = False
            job_reply = "Job request missing auto-reload parameter."
            return job_status, job_reply

        if config.use_api:
            debug_as_thread = False
            if config.debug_level("debug_timings") > 0:
                debug_as_thread = True
            if config.debug_level("debug_profile") > 0:
                debug_as_thread = True
            if debug_as_thread:
                process = False
                thread = True

        # Create job
        job = OTPmeJob(name=name,
                    target_method=target_method,
                    args=_method_args,
                    thread=thread,
                    process=process,
                    timeout=job_timeout,
                    lock_timeout=lock_timeout,
                    reload_objects_on_change=reload_on_change,
                    lock_wait_timeout=lock_wait_timeout,
                    _caller=_caller)

        if not config.use_api:
            try:
                self.check_cluster_status()
            except Exception as e:
                message = str(e)
                status = status_codes.CLUSTER_NOT_READY
                return self.build_response(status, message)
            try:
                current_master_node = multiprocessing.master_node['master']
            except:
                current_master_node = None
            if current_master_node != config.host_data['name']:
                message = "Please connect to master node."
                status = status_codes.CLUSTER_NOT_READY
                return self.build_response(status, message, encrypt=False)

        if thread or process:
            # Start job
            job_reply = job.start()
            # Add job to our job list
            self.jobs[job.uuid] = job
            self.running_jobs[job.uuid] = job
            # Add job to multiprocessing queue.
            if not config.use_api:
                auth_token = "API"
                if config.auth_token:
                    auth_token = config.auth_token.rel_path
                multiprocessing.running_jobs[job.uuid] = {
                                                        'name'      : name,
                                                        'start_time': time.time(),
                                                        'auth_token': auth_token,
                                                        'pid'       : job.pid,
                                                        }
            # Wakeup job handler thread.
            if self.new_job_event:
                self.new_job_event.set()
        else:
            job_reply = job.start()

        return job_reply

    def handle_job(self, job_uuid, callbacks={}, stop=False):
        """ Handle command job. """
        job_status = True
        try:
            job = self.jobs[job_uuid]
        except:
            return False, "Unknown job: %s" % job_uuid

        # Make sure we have at least an empty keepalive message.
        job_reply = send_msg(job_id=job.uuid)

        if stop and job.is_alive():
            try:
                job.stop()
                job_status = True
                stop_result = True
            except JobNotStoppable as e:
                job_status = True
                stop_result = False
                stop_message = "Failed to stop job: %s" % e
            except Exception as e:
                job_status = False
                stop_result = False
                stop_message = ("Terminating job '%s' (%s) failed: %s"
                                % (job.name, job.pid, e))
            while job.is_alive():
                time.sleep(0.001)
            if not stop_result:
                job_reply['message'] = [stop_result, stop_message]
                return job_status, job_reply

        # FIXME: How to implement sending of stop_job command in OTPmeClient()
        #        without replying to keepalive (MSG) messages!?!
        # We need a short keepalive interval to catch stop_job
        # commands from peer.
        keepalive_count = 0
        keepalive_interval = 0.5

        # Get comm handler to communicate with job.
        job_comm_handler = job.comm_queue.get_handler("client")
        # Handle job.
        while True:
            # Get job callbacks.
            if job.is_alive() and callbacks:
                if job_uuid not in self.job_callbacks:
                    self.job_callbacks[job_uuid] = []
                self.job_callbacks[job_uuid].append(callbacks)
                callbacks = None

            # Handle job queries.
            if config.use_api:
                while True:
                    job_queries = False
                    jobs_running = False
                    for job_uuid in dict(self.running_jobs):
                        if self._handle_job_queries(job_uuid) is True:
                            jobs_running = True
                        if job_uuid in self.job_queries:
                            job_queries = True
                    # Continue if no job is running.
                    if not jobs_running:
                        break
                    # Continue if there are job queries
                    if job_queries:
                        break

            # Get job messages/queries.
            try:
                query = self.job_queries[job_uuid].pop(0)
            except:
                query = None
            if query is not None:
                callback_query = query['query']
                job_reply = callback_query
                return job_status, job_reply

            # Process callbacks.
            try:
                job_callbacks = self.job_callbacks.pop(job_uuid)
            except:
                job_callbacks = []
            for x in job_callbacks:
                for answer_id in x:
                    callback_answer = x[answer_id]
                    # Send answer to job.
                    try:
                        job_comm_handler.send(recipient="callback",
                                        command=answer_id,
                                        data=callback_answer)
                    except TimeoutReached:
                        pass
                    except ExitOnSignal:
                        pass

            # Wait for wakeup by job.
            if job.is_alive() and self.new_query_event:
                self.new_query_event.wait(timeout=keepalive_interval)
                self.new_query_event.clear()

            # Check if we reached the keepalive interval
            if keepalive_count >= keepalive_interval:
                break

            keepalive_count += 1

            if job.is_alive():
                continue

            try:
                job_status = self.job_exit_status[job_uuid]['exit_status']
            except:
                continue
            try:
                job_reply = self.job_exit_status[job_uuid]['exit_message']
            except:
                continue
            try:
                objects_written = self.job_exit_status[job_uuid]['objects_written']
            except:
                continue

            if objects_written:
                config.update_data_revision()

            # Close job queues etc.
            job.close()

            # Remove job from list if its no longer alive.
            try:
                self.jobs.pop(job.uuid)
            except KeyError:
                pass

            # Update auth token if needed. There is also some code to update
            # the auth token in OTPmeObject().
            if config.auth_token and job.start_process:
                x = backend.get_object(object_type="token",
                                uuid=config.auth_token.uuid)
                if x != config.auth_token:
                    logger.debug("Reloading modified auth token.")
                    config.auth_token = x
                x = backend.get_object(object_type="user",
                                uuid=config.auth_user.uuid)
                if x != config.auth_user:
                    logger.debug("Reloading modified auth user.")
                    config.auth_user = x

        return job_status, job_reply

    def get_default_unit(self, object_type):
        object_unit = None
        if config.auth_user:
            result = config.auth_user.get_policies(policy_type="defaultunits",
                                                    ignore_hooks=True,
                                                    return_type="instance")
            if result:
                default_units_policy = result[0]
                try:
                    object_unit = default_units_policy.get_default_unit(object_type)
                except NoUnitFound:
                    pass
        if not object_unit:
            object_unit = config.get_default_unit(object_type)
        return object_unit

    def add_object(self, object_type, object_name,
        unit=None, callback=default_callback, **kwargs):
        def signal_handler(_signal, frame):
            """ Handle signals. """
            if config.active_transactions:
                return
            multiprocessing.cleanup()
            if _signal == 15:
                os._exit(1)
            if _signal == 2:
                os._exit(1)
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)

        proctitle = setproctitle.getproctitle()
        proctitle = ("%s: Mass object add %s: %s"
                    % (proctitle, object_type, object_name))
        setproctitle.setproctitle(proctitle)

        multiprocessing.atfork()

        # Get logger.
        logger = config.logger
        # Suppress normal messages.
        callback.only_errors = True
        # Class getter for new object.
        class_getter, \
        getter_args = backend.get_class_getter(object_type)
        # Instantiate class.
        try:
            oc = class_getter()
        except Exception as e:
            msg = "Error loading object class: %s: %s" % (object_type, e)
            logger.warning(msg)
            callback.error(msg)
            sys.exit(1)
        try:
            o = oc(path=None,
                    name=object_name,
                    unit=unit,
                    realm=config.realm,
                    site=config.site,
                    template=False)
        except Exception as e:
            msg = "Error loading object: %s: %s" % (object_name, e)
            logger.warning(msg)
            callback.error(msg)
            sys.exit(1)
        # Add object.
        try:
            add_result = o.add(callback=callback, **kwargs)
        except Exception as e:
            msg = "Failed to add object: %s: %s" % (object_name, e)
            logger.warning(msg)
            callback.error(msg)
            sys.exit(1)
        finally:
            callback.only_errors = False
            multiprocessing.cleanup()
        if add_result:
            callback.write_modified_objects()
            sys.exit(0)
        msg = "Error adding object: %s (See previous errors)" % object_name
        logger.warning(msg)
        callback.error(msg)
        sys.exit(1)

    def mass_object_add(self, csv_data, procs=None, verify_csv=False,
        callback=default_callback, **kwargs):
        """ Handle mass object add. """
        org_termin_signal_handler = signal.getsignal(signal.SIGTERM)
        org_int_signal_handler = signal.getsignal(signal.SIGINT)
        def signal_handler(_signal, frame):
            """ Handle signals. """
            if self.mass_add_procs:
                msg = "Waiting for %s add jobs to finish." % len(self.mass_add_procs)
                callback.send(msg)
            # Kill add processes.
            stuff.kill_pid(pid=os.getpid(),
                        recursive=True,
                        dont_kill_start_pid=True)
            # Wait for add processes to finish.
            while True:
                childs_running = False
                for x_oid in list(self.mass_add_procs):
                    child = self.mass_add_procs[x_oid]
                    if child.is_alive():
                        childs_running = True
                        continue
                    child.join()
                    try:
                        self.mass_add_procs.pop(x_oid)
                    except KeyError:
                        pass
                    time.sleep(0.1)
                if not childs_running:
                    break
            # Update data revision.
            config.update_data_revision()
            if _signal == 15:
                if org_termin_signal_handler:
                    return org_termin_signal_handler(_signal, frame)
            if _signal == 2:
                if org_int_signal_handler:
                    return org_int_signal_handler(_signal, frame)
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)

        if procs is None:
            procs = int(os.cpu_count() / 2)

        def parse_csv_entry(csv_entry):
            #print(csv_entry)
            object_type = csv_entry[0]
            if object_type == "user":
                name = csv_entry[1]
                unit = csv_entry[2]
                group = csv_entry[3]
                groups = csv_entry[4]
                if groups:
                    groups = groups.split(",")
                default_role = csv_entry[5]
                roles = csv_entry[6]
                if roles:
                    roles = roles.split(",")
                default_token_type = csv_entry[7]
                default_token_password = csv_entry[8]
                ldif_attributes = csv_entry[9]
                if not name:
                    msg = "Cannot add user without name"
                    raise OTPmeException(msg)
                method_kwargs = {}
                if unit:
                    method_kwargs['unit'] = unit
                if group:
                    method_kwargs['group'] = group
                if groups:
                    method_kwargs['groups'] = groups
                if default_role:
                    method_kwargs['default_role'] = default_role
                if roles:
                    method_kwargs['default_roles'] = roles
                if default_token_type:
                    method_kwargs['default_token_type'] = default_token_type
                if default_token_password:
                    method_kwargs['password'] = default_token_password
                if ldif_attributes:
                    method_kwargs['ldif_attributes'] = ldif_attributes.split(",")

            elif object_type == "group":
                name = csv_entry[1]
                unit = csv_entry[2]
                ldif_attributes = csv_entry[3]
                if not name:
                    msg = "Cannot add group without name"
                    raise OTPmeException(msg)
                method_kwargs = {}
                if unit:
                    method_kwargs['unit'] = unit
                if ldif_attributes:
                    method_kwargs['ldif_attributes'] = ldif_attributes.split(",")

            elif object_type == "role":
                name = csv_entry[1]
                unit = csv_entry[2]
                groups = csv_entry[3]
                roles = csv_entry[4]
                ldif_attributes = csv_entry[5]
                if groups:
                    groups = groups.split(",")
                if roles:
                    roles = roles.split(",")
                if not name:
                    msg = "Cannot add role without name"
                    raise OTPmeException(msg)
                method_kwargs = {}
                if unit:
                    method_kwargs['unit'] = unit
                if groups:
                    method_kwargs['groups'] = groups
                if roles:
                    method_kwargs['roles'] = roles
                if ldif_attributes:
                    method_kwargs['ldif_attributes'] = ldif_attributes.split(",")
            else:
                msg = "Unsupported object type: %s" % object_type
                raise OTPmeException(msg)
            return object_type, name, unit, method_kwargs

        msg = "Verifying CSV data..."
        callback.send(msg)

        all_users = backend.search(object_type="user",
                                attribute="name",
                                value="*",
                                return_type="name")
        all_groups = backend.search(object_type="group",
                                attribute="name",
                                value="*",
                                return_type="name")
        all_roles= backend.search(object_type="role",
                                attribute="name",
                                value="*",
                                return_type="name")
        line = 0
        callbacks = []
        objects_to_add = []
        id_range_cache = {}
        objects_by_unit = {}
        for entry in csv_data:
            line += 1
            if not entry:
                continue
            try:
                object_type, \
                object_name, \
                object_unit, \
                method_kwargs = parse_csv_entry(entry)
            except Exception as e:
                msg = "Error on line: %s: %s" % (line, e)
                callback.error(msg)
                continue
            # Check if object exists.
            if object_type == "user":
                if object_name in all_users:
                    msg = "%s already exists: %s" % (object_type, object_name)
                    callbacks.append(msg)
                    continue
            elif object_type == "group":
                if object_name in all_groups:
                    msg = "%s already exists: %s" % (object_type, object_name)
                    callbacks.append(msg)
                    continue
            elif object_type == "role":
                if object_name in all_roles:
                    msg = "%s already exists: %s" % (object_type, object_name)
                    callbacks.append(msg)
                    continue
            else:
                msg = "Invalid object type: %s: %s" % (object_type, object_name)
                return callback.error(msg)

            if not object_unit:
                object_unit = self.get_default_unit(object_type)

            idrange_policy = None
            if object_type == "user":
                try:
                    ldif_attributes = method_kwargs['ldif_attributes']
                except KeyError:
                    ldif_attributes = []
                if not any(entry.startswith("uidNumber=") for entry in ldif_attributes):
                    try:
                        idrange_policy = id_range_cache[object_unit]
                    except KeyError:
                        unit_oid = oid.get(object_type="unit",
                                            rel_path=object_unit,
                                            realm=config.realm,
                                            site=config.site)
                        unit = backend.get_object(unit_oid)
                        policies = unit.get_policies(policy_type="idrange",
                                                    return_type="instance")
                        if not policies:
                            site = backend.get_object(object_type="site", uuid=config.site_uuid)
                            policies = site.get_policies(policy_type="idrange",
                                                        return_type="instance")
                        if not policies:
                            realm = backend.get_object(object_type="realm", uuid=config.realm_uuid)
                            policies = realm.get_policies(policy_type="idrange",
                                                        return_type="instance")
                        if not policies:
                            msg = ("No IDRange policy found for %s %s." % (object_type, object_name))
                            return callback.error(msg)
                        idrange_policy = policies[0]
                        id_range_cache[object_unit] = idrange_policy

                    try:
                        by_unit_objects = objects_by_unit[object_unit]['objects'][object_type]
                    except KeyError:
                        by_unit_objects = []
                        objects_by_unit[object_unit] = {}
                        objects_by_unit[object_unit]['policy'] = idrange_policy
                        objects_by_unit[object_unit]['objects'] = {}
                        objects_by_unit[object_unit]['objects'][object_type] = by_unit_objects
                    by_unit_objects.append((object_type, object_name))
            if object_type == "group":
                try:
                    ldif_attributes = method_kwargs['ldif_attributes']
                except KeyError:
                    ldif_attributes = []
                if not any(entry.startswith("gidNumber=") for entry in ldif_attributes):
                    try:
                        idrange_policy = id_range_cache[object_unit]
                    except KeyError:
                        unit_oid = oid.get(object_type="unit",
                                            rel_path=object_unit,
                                            realm=config.realm,
                                            site=config.site)
                        unit = backend.get_object(unit_oid)
                        policies = unit.get_policies(policy_type="idrange",
                                                    return_type="instance")
                        if not policies:
                            site = backend.get_object(object_type="site", uuid=config.site_uuid)
                            policies = site.get_policies(policy_type="idrange",
                                                        return_type="instance")
                        if not policies:
                            realm = backend.get_object(object_type="realm", uuid=config.realm_uuid)
                            policies = realm.get_policies(policy_type="idrange",
                                                        return_type="instance")
                        if not policies:
                            msg = ("No IDRange policy found for %s %s." % (object_type, object_name))
                            return callback.error(msg)
                        idrange_policy = policies[0]
                        id_range_cache[object_unit] = idrange_policy

                    try:
                        by_unit_objects = objects_by_unit[object_unit]['objects'][object_type]
                    except KeyError:
                        by_unit_objects = []
                        objects_by_unit[object_unit] = {}
                        objects_by_unit[object_unit]['policy'] = idrange_policy
                        objects_by_unit[object_unit]['objects'] = {}
                        objects_by_unit[object_unit]['objects'][object_type] = by_unit_objects
                    by_unit_objects.append((object_type, object_name))
            objects_to_add.append((object_type, object_name, object_unit, method_kwargs, idrange_policy))

        callbacks = "\n".join(callbacks)
        callback.error(callbacks)
        if verify_csv:
            return callback.ok()

        msg = "Selecting object IDs..."
        callback.send(msg)

        policy_object_count = {}
        for object_unit in objects_by_unit:
            idrange_policy = objects_by_unit[object_unit]['policy']
            try:
                object_counters = policy_object_count[idrange_policy]
            except KeyError:
                object_counters = {}
                policy_object_count[idrange_policy] = object_counters
            try:
                unit_users = objects_by_unit[object_unit]['objects']['user']
            except KeyError:
                unit_users = []
            try:
                user_counter = object_counters['user']
            except KeyError:
                user_counter = 0
            user_counter += len(unit_users)
            object_counters['user'] = user_counter
            try:
                unit_groups = objects_by_unit[object_unit]['objects']['group']
            except KeyError:
                unit_groups = []
            try:
                group_counter = object_counters['group']
            except KeyError:
                group_counter = 0
            group_counter += len(unit_groups)
            object_counters['group'] = group_counter

        ldif_ids = {}
        for idrange_policy in policy_object_count:
            try:
                user_count = policy_object_count[idrange_policy]['user']
            except KeyError:
                user_count = 0
            try:
                group_count = policy_object_count[idrange_policy]['group']
            except KeyError:
                group_count = 0
            # Get new free ID.
            lock_caller = "mass_object_add"
            idrange_policy.acquire_lock(lock_caller=lock_caller,
                                        write=True,
                                        full=True,
                                        callback=callback)
            uidnumbers = []
            gidnumbers = []
            callback.only_errors = True
            try:
                if user_count:
                    try:
                        uidnumbers = idrange_policy.get_free_ids(object_type="user",
                                                                attribute="uidNumber",
                                                                count=user_count,
                                                                callback=callback)
                    except OTPmeException as e:
                        msg = "Failed to get uidNumbers: %s" % e
                        return callback.error(msg)
                if group_count:
                    try:
                        gidnumbers = idrange_policy.get_free_ids(object_type="group",
                                                                attribute="gidNumber",
                                                                count=group_count,
                                                                callback=callback)
                    except OTPmeException as e:
                        msg = "Failed to get gidNumbers: %s" % e
                        return callback.error(msg)
            finally:
                callback.only_errors = False
                idrange_policy.release_lock(lock_caller=lock_caller)
            ldif_ids[idrange_policy] = {}
            ldif_ids[idrange_policy]['user'] = uidnumbers
            ldif_ids[idrange_policy]['group'] = gidnumbers

        def build_add_message(x_oid, start_time, counter, objects_remaining):
            now = time.time()
            used_time = int(now - start_time)
            per_object_time = used_time / counter
            est_time = now + (per_object_time * objects_remaining)
            duration = est_time - now
            duration = units.int2time(duration, time_unit="s", exact_only=False)
            duration = ":".join(duration)
            est_time = datetime.datetime.fromtimestamp(est_time)
            est_time = est_time.strftime('%H:%M:%S')
            msg = ("Added %s %s (%s/%s) (%.2f): (eta: %s (%s))"
                    % (x_oid.object_type,
                    x_oid.name,
                    counter,
                    objects_count,
                    per_object_time,
                    est_time,
                    duration))
            return msg

        msg = "Processing objects..."
        callback.send(msg)

        prev_object_type = None
        start_time = time.time()
        objects_add_counter = 0
        objects_count = len(objects_to_add)
        for x in objects_to_add:
            object_type = x[0]
            object_name = x[1]
            unit = x[2]
            method_kwargs = x[3]
            idrange_policy = x[4]
            if prev_object_type is None:
                prev_object_type = object_type
            if object_type == "user":
                if idrange_policy:
                    try:
                        ldif_attributes = method_kwargs['ldif_attributes']
                    except KeyError:
                        ldif_attributes = []
                    if not any(entry.startswith("uidNumber=") for entry in ldif_attributes):
                        try:
                            uidnumbers = ldif_ids[idrange_policy]['user']
                        except KeyError:
                            msg = ("Unable to get uidNumber for %s: %s"
                                    % (object_type, object_name))
                            callback.error(msg)
                            continue
                        uidnumber = uidnumbers.pop(0)
                        ldif_attributes.append('uidNumber=%s' % uidnumber)
                        method_kwargs['ldif_attributes'] = ldif_attributes
            if object_type == "group":
                if idrange_policy:
                    try:
                        ldif_attributes = method_kwargs['ldif_attributes']
                    except KeyError:
                        ldif_attributes = []
                    if not any(entry.startswith("gidNumber=") for entry in ldif_attributes):
                        try:
                            gidnumbers = ldif_ids[idrange_policy]['group']
                        except KeyError:
                            msg = ("Unable to get uidNumber for %s: %s"
                                    % (object_type, object_name))
                            callback.error(msg)
                            continue
                        gidnumber = gidnumbers.pop(0)
                        ldif_attributes.append('gidNumber=%s' % gidnumber)
                        method_kwargs['ldif_attributes'] = ldif_attributes

            last_keepalive = time.time()
            while True:
                for x_oid in list(self.mass_add_procs):
                    child = self.mass_add_procs[x_oid]
                    if child.is_alive():
                        keepalive_age = time.time() - last_keepalive
                        if keepalive_age >= 1:
                            last_keepalive = time.time()
                            callback.keepalive()
                        continue
                    child.join()
                    self.mass_add_procs.pop(x_oid)
                    if child.exitcode == 0:
                        objects_add_counter += 1
                        objects_remaining = objects_count - objects_add_counter
                        add_msg = build_add_message(x_oid,
                                                start_time,
                                                objects_add_counter,
                                                objects_remaining)
                        callback.send(add_msg)
                time.sleep(0.01)
                if prev_object_type != object_type:
                    if len(self.mass_add_procs) > 0:
                        continue
                    prev_object_type = object_type
                if len(self.mass_add_procs) < procs:
                    break

            if callback.stop_job:
                break
            # Send keepalive message.
            method_kwargs['gen_qrcode'] = False
            method_kwargs['verify_acls'] = False
            method_kwargs['callback'] = callback
            add_child = multiprocessing.start_process(name="add_object",
                                    target=self.add_object,
                                    target_args=(object_type,
                                                object_name,),
                                    target_kwargs=method_kwargs,
                                    start=False,
                                    daemon=True)
            object_id = ("%s|%s/%s/%s"
                        % (object_type,
                        config.realm,
                        config.site,
                        object_name))
            object_id = oid.get(object_id)
            add_child.start()
            self.mass_add_procs[object_id] = add_child
        # Wait for childs to finish.
        last_keepalive = time.time()
        while True:
            childs_running = False
            for x_oid in list(self.mass_add_procs):
                child = self.mass_add_procs[x_oid]
                if child.is_alive():
                    keepalive_age = time.time() - last_keepalive
                    if keepalive_age >= 1:
                        last_keepalive = time.time()
                        callback.keepalive()
                    childs_running = True
                    continue
                child.join()
                self.mass_add_procs.pop(x_oid)
                if child.exitcode == 0:
                    objects_add_counter += 1
                    objects_remaining = objects_count - objects_add_counter
                    add_msg = build_add_message(x_oid,
                                            start_time,
                                            objects_add_counter,
                                            objects_remaining)
                    callback.send(add_msg)
            if childs_running:
                continue
            break

        # Update data revision.
        config.update_data_revision()
        msg = "Added %s objects." % objects_add_counter
        return callback.ok(msg)

    def verify_cross_site_jwt(self, src_realm, src_site, jwt):
        _src_site = backend.get_object(object_type="site",
                                        realm=src_realm,
                                        name=src_site)
        try:
            jwt_key = RSAKey(key=_src_site._cert.public_key())
        except Exception as e:
            msg = (_("Unable to get public key of site "
                    "certificate: %s: %s") % (src_site, e))
            raise OTPmeException(msg)
        try:
            jwt_data = _jwt.decode(jwt=jwt,
                                key=jwt_key,
                                algorithm='RS256')
        except Exception as e:
            msg = "Failed to decode JWT: %s" % e
            raise OTPmeException(msg)
        return jwt_data

    def verify_move_objects(self, jwt_data, objects):
        """
            Make sure we dont get objects that where not signed by the JWT.
            This check is required to make sure we dont move objects that were
            not show to the user when executing the move command.
        """
        object_ids = jwt_data['object_ids']
        jwt_objects = {}
        for x in object_ids:
            x_oid = x[0]
            x_uuid = x[1]
            jwt_objects[x_oid] = x_uuid
        for x_oid in objects:
            x_oc = objects[x_oid]['object_config']
            x_uuid = x_oc['UUID']
            try:
                y_uuid = jwt_objects[x_oid]
            except KeyError:
                msg = "Got object that was not signed by JWT: %s" % x_oid
                raise OTPmeException(msg)
            if x_uuid == y_uuid:
                continue
            msg = ("Found object UUID missmatch: %s: %s <> %s"
                    % (x_oid, x_uuid, y_uuid))
            raise OTPmeException(msg)

    def build_move_reply(self, moved_objects):
        """ Build reply JWT. """
        our_site = backend.get_object(object_type="site",
                                        realm=config.realm,
                                        name=config.site)
        try:
            jwt_key = RSAKey(key=our_site.key)
        except Exception as e:
            msg = (_("Unable to get public key of site "
                    "certificate: %s: %s") % (our_site, e))
            raise OTPmeException(msg)
        jwt = _jwt.encode(payload=moved_objects,
                        key=jwt_key,
                        algorithm='RS256')
        return jwt

    def move_object(self, command_args):
        jwt = command_args['jwt']
        src_realm = command_args['src_realm']
        src_site = command_args['src_site']

        try:
            jwt_data = self.verify_cross_site_jwt(src_realm, src_site, jwt)
        except Exception as e:
            message = "JWT verification failed"
            msg = "%s: %s" % (message, e)
            self.logger.warning(msg)
            status = False
            return self.build_response(status, message)

        try:
            objects_enc_key = jwt_data['enc_key']
        except KeyError:
            message = "JWT data misses decryption key."
            self.logger.warning(message)
            status = False
            return self.build_response(status, message)

        # Get site cert to decrypt objects and verify reply JWT.
        _dst_site = backend.get_object(object_type="site",
                                        realm=config.realm,
                                        name=config.site)
        # Decrypt encryption key with site private key.
        try:
            site_key = RSAKey(key=_dst_site.key)
        except Exception as e:
            message = (_("Unable to get public key of site "
                    "certificate: %s") % dst_site)
            msg = "%s: %s" % e
            self.logger.warning(msg)
            status = False
            return self.build_response(status, message)
        objects_enc_key = site_key.decrypt(objects_enc_key, encoding="hex")

        # Generate encryption key.
        enc_mod = config.get_encryption_module("FERNET")
        # Encrypt objects.
        objects_encrypted = command_args['objects']
        objects = json.decode(objects_encrypted,
                            encoding="base64",
                            encryption=enc_mod,
                            enc_key=objects_enc_key)

        try:
            self.verify_move_objects(jwt_data, objects)
        except Exception as e:
            message = "Move objects verfication failed: %s" % e
            self.logger.warning(message)
            status = False
            return self.build_response(status, message)

        # Check if objects are moveable.
        for x_src_oid in objects:
            x_oc = objects[x_src_oid]['object_config']
            try:
                x_path = objects[x_src_oid]['path']
            except KeyError:
                x_path = None
            x_src_oid = oid.get(x_src_oid)
            x_uuid = x_oc['UUID']
            x_oid = backend.get_oid(x_uuid)
            if not x_oid:
                message = "Cannot move unknown object: %s" % x_src_oid
                status = False
                return self.build_response(status, message)
            if x_src_oid != x_oid:
                message = ("Cannot move different object: %s <> %s"
                            % (x_src_oid, x_oid))
                status = False
                return self.build_response(status, message)
            if x_src_oid.object_type == "user":
                if not x_path:
                    message = "Missing user path."
                    status = False
                    return self.build_response(status, message)
        # Actually move objects.
        moved_objects = {}
        for x_src_oid in objects:
            x_oc = objects[x_src_oid]['object_config']
            x_policies = objects[x_src_oid]['policies']
            x_src_oid = oid.get(x_src_oid)
            if x_src_oid.object_type == "user":
                try:
                    x_path = objects[x_src_oid]['path']
                except KeyError:
                    message = "Missing user path."
                    status = False
                    return self.build_response(status, message)
                path_data = oid.resolve_path(object_path=x_path,
                                            object_type="unit")
                unit_rel_path = path_data['rel_path']
                result = backend.search(object_type="unit",
                                        attribute="rel_path",
                                        value=unit_rel_path,
                                        return_type="instance",
                                        realm=config.realm,
                                        site=config.site)
                if not result:
                    message = "Unknown unit: %s" % unit_rel_path
                    status = False
                    return self.build_response(status, message)
                dst_unit = result[0]
                if not dst_unit.verify_acl("add:user"):
                    message = "Permission denied: %s" % dst_unit.path
                    status = False
                    return self.build_response(status, message)
                try:
                    backend.delete_object(x_src_oid, cluster=True)
                except UnknownObject:
                    pass
                except Exception as e:
                    message = "Failed to delete object: %s: %s" % (x_src_oid, e)
                    status = False
                    return self.build_response(status, message)
                try:
                    move_object = backend.get_instance_from_oid(x_src_oid, x_oc)
                except Exception as e:
                    message = "Failed to load object: %s: %s" % (x_src_oid, e)
                    status = False
                    return self.build_response(status, message)
                x_dst_oid = "%s|%s/%s/%s/%s" % (x_src_oid.object_type,
                                            config.realm,
                                            config.site,
                                            unit_rel_path,
                                            x_src_oid.name)
                x_dst_oid = oid.get(x_dst_oid)
                move_object.realm = config.realm
                move_object.site = config.site
                move_object.realm_uuid = config.realm_uuid
                move_object.site_uuid = config.site_uuid
                move_object.set_oid(new_oid=x_dst_oid)
                move_object.unit_uuid = dst_unit.uuid
                move_object.set_unit()
                move_object.update_after_move()
                move_object.update_extensions("site_move")
                for policy_name in x_policies:
                    policy_oid = "policy|hboss.intern/koeln/%s" % policy_name
                    policy_oid = oid.get(policy_oid)
                    if not backend.object_exists(policy_oid):
                        continue
                    move_object.add_policy(policy_name, verify_acls=False)
                move_object._write()
                moved_objects[x_src_oid.full_oid] = {}
                moved_objects[x_src_oid.full_oid]['uuid'] = move_object.uuid
                moved_objects[x_src_oid.full_oid]['dst'] = move_object.oid.full_oid
            elif x_src_oid.object_type == "token":
                try:
                    backend.delete_object(x_src_oid, cluster=True)
                except UnknownObject:
                    pass
                except Exception as e:
                    message = "Failed to delete object: %s: %s" % (x_src_oid, e)
                    status = False
                    return self.build_response(status, message)
                try:
                    move_object = backend.get_instance_from_oid(x_src_oid, x_oc)
                except Exception as e:
                    message = "Failed to load object: %s: %s" % (x_src_oid, e)
                    status = False
                    return self.build_response(status, message)
                x_dst_oid = "%s|%s/%s/%s/%s" % (x_src_oid.object_type,
                                            config.realm,
                                            config.site,
                                            x_src_oid.user,
                                            x_src_oid.name)
                x_dst_oid = oid.get(x_dst_oid)
                move_object.realm = config.realm
                move_object.site = config.site
                move_object.realm_uuid = config.realm_uuid
                move_object.site_uuid = config.site_uuid
                move_object.set_oid(new_oid=x_dst_oid)
                move_object.update_extensions("site_move")
                for policy_name in x_policies:
                    policy_oid = "policy|hboss.intern/koeln/%s" % policy_name
                    policy_oid = oid.get(policy_oid)
                    if not backend.object_exists(policy_oid):
                        continue
                    move_object.add_policy(policy_name, verify_acls=False)
                move_object._write()
                moved_objects[x_src_oid.full_oid] = {}
                moved_objects[x_src_oid.full_oid]['uuid'] = move_object.uuid
                moved_objects[x_src_oid.full_oid]['dst'] = move_object.oid.full_oid
            elif x_src_oid.object_type == "group":
                try:
                    x_path = objects[x_src_oid]['path']
                except KeyError:
                    message = "Missing group path."
                    status = False
                    return self.build_response(status, message)
                path_data = oid.resolve_path(object_path=x_path,
                                            object_type="unit")
                unit_rel_path = path_data['rel_path']
                result = backend.search(object_type="unit",
                                        attribute="rel_path",
                                        value=unit_rel_path,
                                        return_type="instance",
                                        realm=config.realm,
                                        site=config.site)
                if not result:
                    message = "Unknown unit: %s" % unit_rel_path
                    status = False
                    return self.build_response(status, message)
                dst_unit = result[0]
                if not dst_unit.verify_acl("add:group"):
                    message = "Permission denied: %s" % dst_unit.path
                    status = False
                    return self.build_response(status, message)
                try:
                    backend.delete_object(x_src_oid, cluster=True)
                except UnknownObject:
                    pass
                except Exception as e:
                    message = "Failed to delete object: %s: %s" % (x_src_oid, e)
                    status = False
                    return self.build_response(status, message)
                try:
                    move_object = backend.get_instance_from_oid(x_src_oid, x_oc)
                except Exception as e:
                    message = "Failed to load object: %s: %s" % (x_src_oid, e)
                    status = False
                    return self.build_response(status, message)
                x_dst_oid = "%s|%s/%s/%s/%s" % (x_src_oid.object_type,
                                            config.realm,
                                            config.site,
                                            unit_rel_path,
                                            x_src_oid.name)
                x_dst_oid = oid.get(x_dst_oid)
                move_object.realm = config.realm
                move_object.site = config.site
                move_object.realm_uuid = config.realm_uuid
                move_object.site_uuid = config.site_uuid
                move_object.set_oid(new_oid=x_dst_oid)
                move_object.unit_uuid = dst_unit.uuid
                move_object.set_unit()
                move_object.update_after_move()
                move_object.update_extensions("site_move")
                for policy_name in x_policies:
                    policy_oid = "policy|hboss.intern/koeln/%s" % policy_name
                    policy_oid = oid.get(policy_oid)
                    if not backend.object_exists(policy_oid):
                        continue
                    move_object.add_policy(policy_name, verify_acls=False)
                move_object._write()
                moved_objects[x_src_oid.full_oid] = {}
                moved_objects[x_src_oid.full_oid]['uuid'] = move_object.uuid
                moved_objects[x_src_oid.full_oid]['dst'] = move_object.oid.full_oid
            else:
                message = "Unknown object type to move: %s" % x_src_oid.object_type
                status = False
                return self.build_response(status, message)

        move_reply = self.build_move_reply(moved_objects)

        return self.build_response(True, move_reply)

    def change_user_default_group(self, command_args):
        jwt = command_args['jwt']
        src_realm = command_args['src_realm']
        src_site = command_args['src_site']

        try:
            jwt_data = self.verify_cross_site_jwt(src_realm, src_site, jwt)
        except Exception as e:
            message = "JWT verification failed"
            msg = "%s: %s" % (message, e)
            self.logger.warning(msg)
            status = False
            return self.build_response(status, message)

        try:
            action = jwt_data['action']
        except KeyError:
            message = "JWT data misses group action."
            self.logger.warning(message)
            status = False
            return self.build_response(status, message)

        try:
            user_name = jwt_data['user_name']
        except KeyError:
            message = "JWT data misses user name."
            self.logger.warning(message)
            status = False
            return self.build_response(status, message)

        try:
            user_uuid = jwt_data['user_uuid']
        except KeyError:
            message = "JWT data misses user UUID."
            self.logger.warning(message)
            status = False
            return self.build_response(status, message)

        result = backend.search(object_type="user",
                                attribute="name",
                                value=user_name,
                                realm=src_realm,
                                site=src_site,
                                return_type="instance")
        if not result:
            message = "Unknown user: %s" % user_name
            self.logger.warning(message)
            status = False
            return self.build_response(status, message)

        _user = result[0]
        if _user.uuid != user_uuid:
            message = ("Got user %s with wrong UUID: %s: %s"
                        % (_user.name, _user.uuid, user_uuid))
            status = False
            return self.build_response(status, message)

        if _user.site != src_site:
            message = ("Got user %s from wrong site: %s"
                        % (_user.name, _user.site))
            status = False
            return self.build_response(status, message)

        if _user.site == config.site:
            message = ("Got user %s from own site: %s"
                        % (_user.name, _user.site))
            status = False
            return self.build_response(status, message)

        try:
            old_group_name = jwt_data['old_group_name']
        except KeyError:
            message = "JWT data misses old group name."
            self.logger.warning(message)
            status = False
            return self.build_response(status, message)

        try:
            old_group_uuid = jwt_data['old_group_uuid']
        except KeyError:
            message = "JWT data misses old group UUID."
            self.logger.warning(message)
            status = False
            return self.build_response(status, message)

        try:
            new_group_name = jwt_data['new_group_name']
        except KeyError:
            message = "JWT data misses new group name."
            self.logger.warning(message)
            status = False
            return self.build_response(status, message)

        try:
            new_group_uuid = jwt_data['new_group_uuid']
        except KeyError:
            message = "JWT data misses new group UUID."
            self.logger.warning(message)
            status = False
            return self.build_response(status, message)

        old_group = None
        if old_group_name:
            result = backend.search(object_type="group",
                                    attribute="name",
                                    value=old_group_name,
                                    realm=config.realm,
                                    site=config.site,
                                    return_type="instance")
            if not result:
                message = "Unknown group: %s" % old_group_name
                self.logger.warning(message)
                status = False
                return self.build_response(status, message)

            old_group = result[0]
            if old_group.uuid != old_group_uuid:
                message = ("Got group %s with wrong UUID: %s: %s"
                            % (old_group.name, old_group.uuid, old_group_uuid))
                status = False
                return self.build_response(status, message)

            if old_group.site != config.site:
                message = ("Got group %s from wrong site: %s" % old_group.site)
                status = False
                return self.build_response(status, message)

        new_group = None
        if new_group_name:
            result = backend.search(object_type="group",
                                    attribute="name",
                                    value=new_group_name,
                                    realm=config.realm,
                                    site=config.site,
                                    return_type="instance")
            if not result:
                message = "Unknown group: %s" % new_group_name
                self.logger.warning(message)
                status = False
                return self.build_response(status, message)

            new_group = result[0]
            if new_group.uuid != new_group_uuid:
                message = ("Got group %s with wrong UUID: %s: %s"
                            % (new_group.name, new_group.uuid, new_group_uuid))
                status = False
                return self.build_response(status, message)

            if new_group.site != config.site:
                message = ("Got group %s from wrong site: %s" % new_group.site)
                status = False
                return self.build_response(status, message)

        if action == "add":
            status = False
            try:
                status = new_group.add_default_group_user(user_uuid=user_uuid,
                                                        callback=default_callback)
            except Exception as e:
                message = "Failed to add default group user: %s" % e
                self.logger.warning(message)
                return self.build_response(status, message)
            if status:
                message = "Added default group user."
            else:
                message = default_callback.job.return_value
        elif action == "remove":
            status = False
            try:
                status = old_group.remove_default_group_user(user_uuid=user_uuid,
                                                            callback=default_callback)
            except Exception as e:
                message = "Failed to remove default group user: %s" % e
                self.logger.warning(message)
                return self.build_response(status, message)
            if status:
                message = "Removed default group user."
            else:
                message = default_callback.job.return_value
        elif action == "change":
            status = False
            message = "Users default group changed."
            # Remove user from old group.
            try:
                status = old_group.remove_default_group_user(user_uuid=user_uuid,
                                                            callback=default_callback)
            except Exception as e:
                message = "Failed to remove default group user: %s" % e
                self.logger.warning(message)
                return self.build_response(status, message)
            if status:
                # Add user to new group.
                try:
                    status = new_group.add_default_group_user(user_uuid=user_uuid,
                                                            callback=default_callback)
                except Exception as e:
                    message = "Failed to add default group user: %s" % e
                    self.logger.warning(message)
                    return self.build_response(status, message)
                if not status:
                    message = "Failed to set users default group."
            else:
                message = "Failed to unset users default group."

        if not status:
            return self.build_response(status, message)

        # Build JWT reply.
        our_site = backend.get_object(object_type="site",
                                        realm=config.realm,
                                        name=config.site)
        try:
            jwt_key = RSAKey(key=our_site.key)
        except Exception as e:
            msg = (_("Unable to get public key of site "
                    "certificate: %s: %s") % (our_site, e))
            raise OTPmeException(msg)

        jwt = _jwt.encode(payload=jwt_data,
                        key=jwt_key,
                        algorithm='RS256')

        return self.build_response(True, jwt)

    def handle_backend_commands(self, backend_command, command_args):
        """ Handle 'backend' commands. """
        status = False
        response = ""

        valid_backend_commands = [  "search",
                                    "import",
                                    "restore",
                                    "get_uuid",
                                ]

        if len(backend_command) < 2:
            status = False
            message = "Missing backend sub command: %s" % backend_command
            return self.build_response(status, message)

        # Check if we got a valid command
        if not backend_command in valid_backend_commands:
            status = False
            message = "Unknown command: %s" % backend_command
            return self.build_response(status, message)

        if backend_command == "get_uuid":
            try:
                object_id = command_args['object_id']
            except:
                message = "MGMT_INCOMPLETE_COMMAND"
                status = False
                return self.build_response(status, message)

            object_id = oid.get(object_id=object_id)
            try:
                response = backend.get_uuid(object_id)
                status = True
            except Exception as e:
                response = "Error getting UUID: %s: %s" % (object_id, e)
                status = False
                config.raise_exception()

        if backend_command == "import":
            if not self.is_admin:
                status = False
                message = "You need to be admin to run this command."
                return self.build_response(status, message)

            try:
                object_id = command_args['object_id']
            except:
                message = "MGMT_INCOMPLETE_COMMAND"
                status = False
                return self.build_response(status, message)
            try:
                password = command_args['password']
            except:
                password = None

            # Decode object config and convert it to dict.
            object_config = command_args.pop("object_config")
            object_config = json.decode(object_config, encoding="base64")

            try:
                key_salt = object_config.pop("ENC_SALT")
            except:
                key_salt = None

            aes_key = None
            if password:
                if not key_salt:
                    status = False
                    message = "Object config misses encryption key salt."
                    return self.build_response(status, message)
                x = encryption.derive_key(password, salt=key_salt,
                            hash_type=config.object_export_hash_type)
                aes_key = x['key']
            if key_salt:
                if not password:
                    status = False
                    message = "Object config is encrypted. Use --password."
                    return self.build_response(status, message)

            opt_args = {}
            args = {
                'aes_key'       : aes_key,
                'object_id'     : object_id,
                'object_config' : object_config,
            }

            try:
                status, \
                response = self.start_job(name="import_object",
                                    target_method=backend.import_config,
                                    args=args, opt_args=opt_args,
                                    command_args=command_args,
                                    process=True,
                                    thread=False)
            except Exception as e:
                config.raise_exception()
                response = ("Error running command: %s: %s"
                                % (backend_command, e))
                status = False

        if backend_command == "restore":
            if not self.is_admin:
                status = False
                message = "You need to be admin to run this command."
                return self.build_response(status, message)
            try:
                object_data = command_args['object_data']
            except:
                message = "MGMT_INCOMPLETE_COMMAND"
                status = False
                return self.build_response(status, message)

            args = {'object_data':object_data}
            try:
                status, \
                response = self.start_job(name="restore_object",
                                    target_method=backup.restore_object,
                                    args=args, command_args=command_args,
                                    process=True,
                                    thread=False)
            except Exception as e:
                config.raise_exception()
                response = ("Error running command: %s: %s"
                                % (backend_command, e))
                status = False

        if backend_command == "search":
            try:
                search_command = command_args['search_command']
                search_command = " ".join(search_command)
                search_command = decode(search_command, "base64")
                search_command = search_command.split("\0")
            except:
                message = "MGMT_INCOMPLETE_COMMAND"
                status = False
                return self.build_response(status, message)
            object_type = None
            attribute = None
            value = None
            return_type = "full_oid"

            for p in search_command:
                try:
                    n, v = p.split("=")
                    # replace leading whitespace (allow ", " as delemiter on command line)
                    n = re.sub('^[ ]*', r'', n)
                    if n == "object_type":
                        object_type = v
                    if n == "attribute":
                        attribute = v
                    if n == "value":
                        value = v
                    if n == "return_type":
                        return_type = v
                except:
                    message = "Syntax error: %s" % search_command
                    status = False
                    return self.build_response(status, message)

            if not attribute or (attribute and not value):
                message = "MGMT_INCOMPLETE_COMMAND"
                status = False
                return self.build_response(status, message)

            verify_acls = []
            if not self.is_admin:
                # Build ACL that checks if user is allowed to search the attribute.
                if attribute.startswith("ldif:"):
                    acl = "view_public:attribute:%s" % attribute
                else:
                    acl = "view_public:%s" % attribute
                verify_acls = [acl]

            # Check for integer attribute.
            if attribute.startswith("ldif:"):
                at = ":".join(attribute.split(":")[1:])
                at_type = config.ldap_attribute_types[at].equality
                if at_type == "integerMatch":
                    value = int(value)

            try:
                search_result = backend.search(attribute=attribute,
                                                value=value,
                                                object_type=object_type,
                                                return_type=return_type,
                                                verify_acls=verify_acls,
                                                realm=config.realm,
                                                site=config.site)
                # Make sure we return all results as str().
                if return_type == "checksum":
                    response = "\n".join("%s %s" % (str(x[0]), str(x[1]))
                                                for x in search_result)
                else:
                    response = "\n".join(str(x) for x in search_result)
                status = True
            except SizeLimitExceeded as e:
                response = e
                status = False
            except SearchException as e:
                response = "Error running search: %s" % e
                status = False
            except UnknownObjectType as e:
                response = "Error running search: %s" % e
                status = False
            except Exception as e:
                #config.raise_exception()
                response = "Internal server error."
                msg = "Unhandled exception running search: %s" % e
                logger.critical(msg)

        return self.build_response(status, response)

    def handle_trash_commands(self, trash_command, command_args):
        """ Handle 'trash' commands. """
        from otpme.lib.trash import empty
        from otpme.lib.trash import delete
        from otpme.lib.trash import restore
        from otpme.lib.trash import show_trash
        status = False
        response = ""

        valid_backend_commands = [  "show",
                                    "restore",
                                    "empty",
                                    "del",
                                ]

        if len(trash_command) < 2:
            status = False
            message = "Missing backend sub command: %s" % trash_command
            return self.build_response(status, message)

        # Check if we got a valid command
        if not trash_command in valid_backend_commands:
            status = False
            message = "Unknown command: %s" % trash_command
            return self.build_response(status, message)

        try:
            _args = command_map['trash']['exists'][trash_command]['args']
        except KeyError:
            _args = []

        try:
            _opt_args = command_map['trash']['exists'][trash_command]['oargs']
        except KeyError:
            _opt_args = []

        try:
            job_type = command_map['trash']['exists'][trash_command]['job_type']
        except:
            job_type = "thread"

        if job_type == "thread":
            job_thread = True
            job_process = False
        elif job_type == "process":
            job_process = True
            job_thread = False
        elif job_type is None:
            job_process = False
        else:
            msg = "Unknown job type: %s" % job_type
            raise OTPmeException(msg)

        if trash_command == "show":
            try:
                status, \
                response = self.start_job(name="trash_show",
                                    target_method=show_trash,
                                    args={}, _args=_args,
                                    _opt_args=_opt_args,
                                    command_args=command_args,
                                    process=job_process,
                                    thread=job_thread)
            except Exception as e:
                config.raise_exception()
                response = ("Error running command: %s: %s"
                                % (backend_command, e))

        if trash_command == "restore":
            try:
                trash_id = command_args.pop('object_identifier')
                command_args['trash_id'] = trash_id
            except:
                message = "MGMT_INCOMPLETE_COMMAND"
                status = False
                return self.build_response(status, message)

            try:
                status, \
                response = self.start_job(name="trash_restore",
                                    target_method=restore,
                                    args={}, _args=_args,
                                    _opt_args=_opt_args,
                                    command_args=command_args,
                                    process=job_process,
                                    thread=job_thread)
            except Exception as e:
                config.raise_exception()
                response = ("Error running command: %s: %s"
                                % (backend_command, e))

        if trash_command == "del":
            try:
                trash_id = command_args.pop('object_identifier')
                command_args['trash_id'] = trash_id
            except:
                message = "MGMT_INCOMPLETE_COMMAND"
                status = False
                return self.build_response(status, message)

            try:
                status, \
                response = self.start_job(name="trash_delete",
                                    target_method=delete,
                                    args={}, _args=_args,
                                    _opt_args=_opt_args,
                                    command_args=command_args,
                                    process=job_process,
                                    thread=job_thread)
            except Exception as e:
                config.raise_exception()
                response = ("Error running command: %s: %s"
                                % (backend_command, e))

        if trash_command == "empty":
            if not self.is_admin:
                status = False
                message = "You need to be admin to run this command."
                return self.build_response(status, message)
            try:
                status, \
                response = self.start_job(name="trash_empty",
                                    target_method=empty,
                                    args={}, _args=_args,
                                    _opt_args=_opt_args,
                                    command_args=command_args,
                                    process=job_process,
                                    thread=job_thread)
            except Exception as e:
                config.raise_exception()
                response = ("Error running command: %s: %s"
                                % (backend_command, e))

        return self.build_response(status, response)

    def _process(self, command, command_args, **kwargs):
        """ Handle management commands received from connection handler. """
        # Default response should be emtpy.
        response = ""
        # Indicates if the command was successful.
        status = False
        # Will hold callbacks.
        callbacks = {}

        # Check if we got a valid command
        if command not in valid_commands:
            status = False
            message = "Unknown command: %s" % command
            return self.build_response(status, message)

        # mgmtd does require an authenticated user.
        if not self.authenticated or not self.username or not config.auth_token:
            if config.daemon_mode:
                status = status_codes.NEED_USER_AUTH
                message = "Please auth first."
                return self.build_response(status, message)

        # Check if authenticated user is admin.
        self.is_admin = False
        if config.auth_token:
            if config.auth_token.is_admin():
                self.is_admin = True
        elif config.use_api:
            self.is_admin = True

        # Try to get job UUID and callbacks.
        try:
            job_uuid = command_args.pop('job_uuid')
        except KeyError:
            job_uuid = None

        # If a job exists handle it.
        if job_uuid:
            # Get callbacks
            for i in dict(command_args):
                if not i.startswith("callback:"):
                    continue
                callbacks[i] = command_args.pop(i)

            if command == "stop_job":
                stop = True
            else:
                stop = False
            # Handle job callbacks
            status, \
            response = self.handle_job(job_uuid=job_uuid,
                                    callbacks=callbacks,
                                    stop=stop)

            return self.build_response(status, response)

        if not config.use_api:
            try:
                self.check_cluster_status()
            except Exception as e:
                message = str(e)
                status = status_codes.CLUSTER_NOT_READY
                return self.build_response(status, message)

        # If no job exists handle commands.
        args = {}
        opt_args = {}
        sub_type = None
        object_type = None

        # Get subcommand.
        try:
            subcommand = command_args['subcommand']
        except KeyError:
            status = False
            response = "Missing subcommand."
            return self.build_response(status, response)

        # Check if we got a "object command" (e.g. user, group ...)
        if command in config.tree_object_types or command == "session":
            object_type = command

        # Handle get share command.
        if command == "get_share":
            try:
                share_id = command_args['share_id']
            except KeyError:
                status = False
                response = "Missing <share_id>"
                return self.build_response(status, response)
            try:
                share_site = share_id.split("/")[0]
                share_name = share_id.split("/")[1]
            except:
                status = False
                response = "Invalid share id: %s" % share_id
                return self.build_response(status, response)
            result = backend.search(object_type="share",
                                    attribute="name",
                                    value=share_name,
                                    realm=config.realm,
                                    site=share_site,
                                    return_type="instance")
            if not result:
                status = False
                response = "Unknown share: %s" % share_name
                return self.build_response(status, response)
            share = result[0]
            shares = {}
            share_nodes = share.get_nodes(include_pools=True,
                                        return_type="instance")
            if not share_nodes:
                share_nodes = backend.search(object_type="node",
                                            attribute="uuid",
                                            value="*",
                                            realm=share.realm,
                                            site=share.site,
                                            return_type="instance")
            if share_nodes:
                node_fqdns = []
                for node in share_nodes:
                    node_fqdns.append(node.fqdn)
                share_id = "%s/%s" % (share.site, share.name)
                shares[share_id] = {}
                shares[share_id]['name'] = share.name
                shares[share_id]['site'] = share.site
                shares[share_id]['nodes'] = node_fqdns
                shares[share_id]['encrypted'] = share.encrypted
            status = True
            return self.build_response(status, shares)

        # Handle get share command.
        if command == "get_shares":
            search_attrs = {
                            'token' : {'value':config.auth_token.uuid},
                        }
            user_shares = backend.search(object_type="share",
                                        attributes=search_attrs,
                                        return_type="instance")
            token_roles = config.auth_token.get_roles(return_type="uuid", recursive=True)
            if token_roles:
                search_attrs = {
                                'role' : {'values':token_roles},
                            }
                user_shares += backend.search(object_type="share",
                                            attributes=search_attrs,
                                            return_type="instance")
            shares = {}
            for share in user_shares:
                share_nodes = share.get_nodes(include_pools=True,
                                            return_type="instance")
                if not share_nodes:
                    share_nodes = backend.search(object_type="node",
                                                attribute="uuid",
                                                value="*",
                                                realm=share.realm,
                                                site=share.site,
                                                return_type="instance")
                if share_nodes:
                    node_fqdns = []
                    for node in share_nodes:
                        node_fqdns.append(node.fqdn)
                    share_id = "%s/%s" % (share.site, share.name)
                    shares[share_id] = {}
                    shares[share_id]['name'] = share.name
                    shares[share_id]['site'] = share.site
                    shares[share_id]['nodes'] = node_fqdns
                    shares[share_id]['encrypted'] = share.encrypted
            status = True
            return self.build_response(status, shares)

        # Handle get token type command.
        if command == "get_token_type":
            try:
                token_path = command_args['token_path']
            except KeyError:
                status = False
                response = "Missing <token_path>"
                return self.build_response(status, response)
            return_attrs = ['token_type']
            result = backend.search(object_type="token",
                                    attribute="rel_path",
                                    value=token_path,
                                    return_attributes=return_attrs)
            if not result:
                status = False
                response = "Unknown token: %s" % token_path
                return self.build_response(status, response)
            status = True
            response = result[0]
            return self.build_response(status, response)

        # Handle get policy type command.
        if command == "get_policy_type":
            try:
                policy_name = command_args['policy_name']
            except KeyError:
                status = False
                response = "Missing <policy_name>"
                return self.build_response(status, response)
            return_attrs = ['policy_type']
            result = backend.search(object_type="policy",
                                    attribute="name",
                                    value=policy_name,
                                    return_attributes=return_attrs)
            if not result:
                status = False
                response = "Unknown policy: %s" % policy_name
                return self.build_response(status, response)
            status = True
            response = result[0]
            return self.build_response(status, response)

        # Handle clear reauth command.
        if command == "reset_reauth":
            try:
                config.last_reauth.pop(config.auth_token.uuid)
            except KeyError:
                pass
            return self.build_response(True, None)

        # Handle change user defafult group command.
        if command == "change_user_default_group":
            return self.change_user_default_group(command_args)

        # Handle move objects command.
        if command == "move_object":
            return self.move_object(command_args)

        # Handle backend commands.
        if command == "backend":
            return self.handle_backend_commands(subcommand, command_args)

        # Handle trash commands.
        if command == "trash":
            return self.handle_trash_commands(subcommand, command_args)

        if command == "check_duplicate_ids":
            if subcommand == "user":
                id_attribute = "ldif:uidNumber"
            elif subcommand == "group":
                id_attribute = "ldif:gidNumber"
            else:
                status = False
                response = "Need <user> or <group>."
                return self.build_response(status, response)


            result = backend.search(object_type=subcommand,
                                    attribute=id_attribute,
                                    greater_than=-1,
                                    return_attributes=['name', id_attribute])
            all_uids = {}
            duplicates = []
            for x in result:
                x_name = result[x]['name']
                x_uid = result[x][id_attribute][0]
                if x_uid in all_uids:
                    x_dup = all_uids[x_uid]
                    duplicates.append([x_uid, x_name, x_dup])
                all_uids[x_uid] = x_name

            response = "No duplicate IDs found."
            if duplicates:
                response = pprint.pformat(duplicates)
            status = True

            return self.build_response(status, response)

        # Handle dump_object command.
        if command == "dump_object":
            if self.is_admin:
                try:
                    object_id = command_args['object_id']
                    object_id = oid.get(object_id=object_id)
                except Exception as e:
                    object_id = None
                    status = False
                    response = str(e)
                if object_id:
                    if backend.object_exists(object_id):
                        object_config = backend.read_config(object_id)
                        response = object_config.copy()
                        status = True
                    else:
                        response = "Object does not exist."
                        status = False
                else:
                    response = "Need OID."
                    status = False
            else:
                response = "Permission denied."
                status = False
            return self.build_response(status, response)

        # Handle delete_object command.
        if command == "delete_object":
            def delete_object(object_id, force=False, verbose_level=0,
                callback=default_callback, **kwargs):
                object_id = oid.get(object_id=object_id)
                if not backend.index_get(object_id):
                    if not backend.object_exists(object_id):
                        return callback.error("Object does not exist.")
                if not force:
                    ask = callback.ask("Delete object? ")
                    if str(ask).lower() != "y":
                        return callback.abort()
                try:
                    backend.delete_object(object_id, cluster=True)
                except Exception as e:
                    msg = "Error deleting object: %s" % e
                    return callback.error(msg)
                config.update_data_revision()
                return callback.ok()

            if self.is_admin:
                try:
                    object_id = command_args['object_id']
                except Exception as e:
                    object_id = None
                    status = False
                    response = str(e)
                if object_id:
                    try:
                        status, \
                        response = self.start_job(name="delete_object",
                                            target_method=delete_object,
                                            command_args=command_args,
                                            _args=['object_id'],
                                            process=True,
                                            thread=False)
                    except Exception as e:
                        config.raise_exception()
                        response = ("Error running command: %s: %s"
                                % (command, e))
                        status = False
            else:
                response = "Permission denied."
                status = False

        # Handle mass object add command.
        if command == "mass_object_add":
            status = True
            if not self.is_admin:
                response = "Permission denied."
                status = False
            if status:
                if "csv_data" not in command_args:
                    status = False
                    response = "Missing csv data."
                if status:
                    try:
                        status, \
                        response = self.start_job(name="mass_object_add",
                                            target_method=self.mass_object_add,
                                            command_args=command_args,
                                            _args=['csv_data'],
                                            _opt_args=['verify_csv', 'procs'],
                                            process=True,
                                            thread=False)
                    except Exception as e:
                        config.raise_exception()
                        response = ("Error running command: %s: %s"
                                % (command, e))
                        status = False
                    return self.build_response(status, response)

        # Handle dump_index command.
        if command == "dump_index":
            if self.is_admin:
                try:
                    object_id = command_args['object_id']
                    object_id = oid.get(object_id=object_id)
                except Exception as e:
                    object_id = None
                    status = False
                    response = str(e)

                if object_id:
                    try:
                        response = backend.index_dump(object_id=object_id,
                                                    checksum_ready=True)
                        status = True
                    except Exception as e:
                        status = False
                        response = str(e)
            else:
                response = "Permission denied."
                status = False
            return self.build_response(status, response)


        # Handle object commands.
        object_status = "missing"
        response = "MGMT_INVALID_SYNTAX: Missing %s name" % command
        object_name = None
        object_unit = None
        object_path = None
        job_type = "thread"
        job_name = None
        o = None

        # Try to get object identifier from command.
        try:
            object_identifier = command_args['object_identifier']
        except:
            object_identifier = None

        if object_identifier:
            # Handle tree objects.
            if object_type:
                if object_type == "session":
                    session_id = object_identifier
                    try:
                        o = backend.get_sessions(session_id=session_id,
                                                return_type="instance")[0]
                        object_status = "exists"
                    except:
                        response = "MGMT_INVALID_SESSION_ID: %s" % object_identifier
                else:
                    # Check if we add a template.
                    template = False
                    if subcommand == "add":
                        try:
                            template = command_args['template']
                        except:
                            pass

                    # Resolv object path (e.g. user/token)
                    object_rel_path = None
                    if "/" in object_identifier:
                        x = oid.resolve_path(object_identifier,
                                            object_type=object_type)
                        object_name = x['name']
                        object_unit = x['unit']

                        if object_identifier.startswith("/"):
                            object_path = object_identifier
                        else:
                            object_rel_path = object_identifier
                    else:
                        object_name = object_identifier
                        object_rel_path = object_identifier

                    if subcommand == "add" and not object_unit:
                        try:
                            object_unit = command_args['_object_unit']
                        except:
                            if template:
                                try:
                                    object_unit = config.get_default_unit("template")
                                except:
                                    pass
                            else:
                                try:
                                    object_unit = self.get_default_unit(object_type)
                                except:
                                    pass

                    # Check if object name does contain invalid chars.
                    if oid.check_name(object_type, object_name):
                        result = None
                        attribute = "name"
                        search_value = object_name

                        # We need to search for existing tokens by rel_path.
                        if object_type == "token":
                            attribute = "rel_path"
                            search_value = object_rel_path
                        # We need to search for existing scripts by rel_path.
                        if object_type == "script":
                            attribute = "rel_path"
                            search_value = object_rel_path
                        # We need to search for existing units by rel_path.
                        if object_type == "unit":
                            attribute = "rel_path"
                            search_value = object_rel_path

                        # Allow dump of public key for users from all sites (used by key script on share mount).
                        search_site = config.site
                        if command == "user" and subcommand == "dump_key":
                            search_site = None

                        # Check if we can find the object on our site.
                        if object_type != "realm" and object_type != "site":
                            # Search for existing object of our own site.
                            try:
                                result = backend.search(object_type=object_type,
                                                        attribute=attribute,
                                                        value=search_value,
                                                        return_type="instance",
                                                        realm=config.realm,
                                                        site=search_site)
                            except LockWaitTimeout as e:
                                message = "Object locked: %s" % e
                                status = False
                                return self.build_response(status, message)
                            except OTPmeException as e:
                                message = "Error: %s" % e
                                status = False
                                return self.build_response(status, message)
                        if result:
                            o = result[0]
                            if o.exists(run_policies=True):
                                object_status = "exists"

                        # If we found no object we have to check if this is a
                        # request to add a new object.
                        elif subcommand == "add" or subcommand == "init":
                            # Class getter for new object.
                            class_getter, \
                            getter_args = backend.get_class_getter(object_type)
                            # Get args to get class (e.g. policy type).
                            _getter_args = {}
                            if getter_args:
                                for x in getter_args:
                                    x_arg = getter_args[x]
                                    if x_arg not in command_args:
                                        message = "Missing argument: %s" % x_arg
                                        status = False
                                        return self.build_response(status, message)
                                _getter_args[x_arg] = command_args[x_arg]
                            # Get class.
                            oc = class_getter(**_getter_args)
                            # Instantiate class.
                            try:
                                o = oc(path=object_path,
                                        name=object_name,
                                        unit=object_unit,
                                        realm=config.realm,
                                        site=config.site,
                                        template=template)
                            except Exception as e:
                                config.raise_exception()
                                object_status = "failure"
                                response = "Error loading object: %s" % e

                        # If this is not a request to add a new object to our
                        # site we have to check if we can find the object on an
                        # other site.
                        else:
                            if object_type == "realm":
                                search_realm = None
                                search_site = None
                            elif object_type == "site":
                                search_realm = config.realm
                                search_site = None
                            else:
                                search_realm = config.realm
                                search_site = config.site

                            # Search for existing object of all sites.
                            result = backend.search(object_type=object_type,
                                                    attribute=attribute,
                                                    value=object_identifier,
                                                    return_type="instance",
                                                    site=search_site,
                                                    realm=search_realm)
                            if result:
                                o = result[0]
                                if o.exists(run_policies=True):
                                    object_status = "exists"
                                if not config.use_api:
                                    if o.type == "site":
                                        site_realm = backend.get_object(object_type="realm",
                                                                        uuid=o.realm_uuid)
                                        master_site = backend.get_object(object_type="site",
                                                                        uuid=site_realm.master)
                                        if not master_site:
                                            message = (_("Unknown site: %s") % site_realm.master)
                                            status = False
                                            return self.build_response(status, message)
                                        # On site delete we must redirect to the master site.
                                        if subcommand == "del":
                                            if master_site.uuid != config.site_uuid:
                                                message = (_("You have to delete sites on the master site."))
                                                status = False
                                                return self.build_response(status, message)

                    elif subcommand != "show":
                        response = "MGMT_INVALID_OBJECT_NAME: %s" % object_name
                        object_status = "failure"

        # Handle some special commands.
        if object_type == "realm":
            if object_status == "exists":
                command_done = False
                if subcommand == "_show_extensions":
                    response = "\n".join(config.extensions)
                    status = True
                    command_done = True

                elif subcommand == "_show_hash_types":
                    response = str("\n".join(hashlib.algorithms))
                    status = True
                    command_done = True

                elif subcommand == "_show_token_types":
                    token_types = config.get_sub_object_types("token")
                    response = "\n".join(token_types)
                    status = True
                    command_done = True

                elif subcommand == "_show_policy_types":
                    supported_policy_types = config.get_sub_object_types("policy")
                    response = "\n".join(supported_policy_types)
                    status = True
                    command_done = True

                elif subcommand == "_show_resolver_types":
                    supported_resolver_types = config.get_sub_object_types("resolver")
                    response = "\n".join(supported_resolver_types)
                    status = True
                    command_done = True

                elif subcommand == "_show_valid_search_attributes":
                    from otpme.lib.extensions import utils
                    utils.load_schemas()
                    ldap_attributes = list(config.ldap_attribute_types)
                    ldap_attributes.sort()
                    otpme_attributes = list(config.otpme_base_attributes)
                    otpme_attributes.sort()
                    search_attributes = otpme_attributes + ["ldif:" + str(i) for i in ldap_attributes]
                    response = str("\n".join(search_attributes))
                    status = True
                    command_done = True

                if command_done:
                    return self.build_response(status, response)
            else:
                if subcommand == "init":
                    if not config.use_api:
                        response = ("MGMT_UNKNOWN_COMMAND: %s %s"
                                    % (command, subcommand))
                    args = {
                        'realm_master'  : None,
                        'site_address'  : None,
                        'site_fqdn'     : None,
                    }

        # Get object sub type.
        try:
            sub_type_attribute = sub_types[object_type]
            #sub_type = getattr(o, sub_type_attribute)
            sub_type = command_args[sub_type_attribute]
        except:
            pass
        # Try to get command methods.
        try:
            x_type = object_type
            if sub_type:
                x_type = "%s:%s" % (object_type, sub_type)
            try:
                method = command_map[x_type][object_status][subcommand]['method']
            except:
                method = command_map[object_type][object_status][subcommand]['method']

            if isinstance(method, str):
                command_method = getattr(o, method)
            else:
                command_method = method
        except:
            command_method = None

        if object_name and not command_method:
            try:
                _test = command_map[x_type][object_status]
            except:
                try:
                    _test = command_map[object_type][object_status]
                except:
                    _test = False

            if _test:
                response = ("MGMT_UNKNOWN_OBJECT: %s"
                            % object_identifier)
                status = False
            else:
                response = ("MGMT_UNKNOWN_COMMAND: %s %s"
                            % (command, subcommand))
                status = False

        if command_method:
            # Show command needs special handling.
            if subcommand == "show":
                args = { 'realm' : config.realm }
                opt_args = { 'site' : config.site }
                if object_status == "missing":
                    # With object_name given we will do a regex search.
                    if object_identifier:
                        opt_args['search_regex'] = object_identifier

            # Get required args.
            try:
                _args = command_map[x_type][object_status][subcommand]['args']
            except KeyError:
                try:
                    _args = command_map[object_type][object_status][subcommand]['args']
                except KeyError:
                    _args = {}
            # Get optional args.
            try:
                _opt_args = command_map[x_type][object_status][subcommand]['oargs']
            except:
                try:
                    _opt_args = command_map[object_type][object_status][subcommand]['oargs']
                except KeyError:
                    _opt_args = []
            # Get default args.
            try:
                _dargs = command_map[x_type][object_status][subcommand]['dargs']
            except KeyError:
                try:
                    _dargs = command_map[object_type][object_status][subcommand]['dargs']
                except KeyError:
                    _dargs = {}
            try:
                job_type = command_map[x_type][object_status][subcommand]['job_type']
            except:
                job_type = command_map[object_type][object_status][subcommand]['job_type']

            if job_type == "thread":
                job_thread = True
                job_process = False
            elif job_type == "process":
                job_process = True
                job_thread = False
            elif job_type is None:
                job_process = False
            else:
                msg = "Unknown job type: %s" % job_type
                raise OTPmeException(msg)

            # In API mode with enabled debug timing of method calls we must
            # start jobs as threads instead of sub processes to catch all
            # method calls.
            if config.use_api and config.debug_level("debug_timings") > 0:
                if job_process:
                    job_process = False
                    job_thread = False

            # Build job name.
            job_name = "%s %s" % (object_type, subcommand)
            if object_name:
                job_name = "%s %s" % (job_name, object_name)

            if job_type is None:
                _method_args = self.get_method_args(command_args, args, _args, opt_args, _opt_args, _dargs)
                try:
                    response = command_method(**_method_args)
                    status = True
                except Exception as e:
                    response = "Failed to run command: %s" % e
                    status = False
                    config.raise_exception()
            else:
                try:
                    status, \
                    response = self.start_job(name=job_name,
                                        target_method=command_method,
                                        args=args, _args=_args,
                                        opt_args=opt_args,
                                        _opt_args=_opt_args,
                                        _dargs=_dargs,
                                        command_args=command_args,
                                        process=job_process,
                                        thread=job_thread)
                except Exception as e:
                    response = ("Error running command: %s: %s"
                                        % (subcommand, e))
                    status = False
                    config.raise_exception()

        return self.build_response(status, response)

    def _close(self):
        """ Stop ourselves. """
        pass
