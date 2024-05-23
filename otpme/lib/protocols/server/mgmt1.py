# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time
import signal
import pprint
import hashlib
import threading

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import re
from otpme.lib import oid
from otpme.lib import json
from otpme.lib import config
from otpme.lib import backend
from otpme.lib import encryption
from otpme.lib import jwt as _jwt
from otpme.lib import multiprocessing
from otpme.lib.encoding.base import decode
from otpme.lib.encryption.rsa import RSAKey
from otpme.lib.protocols import status_codes
from otpme.lib.job.otpme_job import OTPmeJob
from otpme.lib.protocols.utils import send_msg
from otpme.lib.protocols.otpme_server import OTPmeServer1

from otpme.lib.exceptions import *

logger = config.logger

sub_types = {}
command_map = {}

# All valid commands
valid_commands = [
                'backend',
                'stop_job',
                'move_object',
                'dump_index',
                'dump_object',
                'reset_reauth',
                'delete_object',
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
        # Inherit tokens from parent accessgroups?
        self.check_parent_groups = False
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
                    job.join()
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
            except:
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
        job.join()
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

    def get_method_args(self, command_args, args, opt_args, default_args):
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

        # Get default args.
        for a in default_args:
            _method_args[a] = default_args[a]

        # Get mandatory args.
        for a in args:
            try:
                _method_args[a] = command_args[a]
                command_args.pop(a)
            except:
                # Try to get default value from method args.
                try:
                    _method_args[a] = args[a]
                except:
                    # If args and command_args misses a required arg the
                    # command is incomplete.
                    return False

        # Get optional args.
        for a in opt_args:
            if opt_args[a] is None:
                try:
                    _method_args[a] = command_args[a]
                    command_args.pop(a)
                except:
                    pass
            else:
                _method_args[a] = opt_args[a]

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

    def start_job(self, name, target_method, args={}, opt_args={},
        default_args={}, command_args={}, thread=True, process=False):
        """ Start command as child process. """
        if len(self.running_jobs) >= self.max_jobs:
            job_reply = "Max jobs reached (%s)" % self.max_jobs
            return False, job_reply
        # Get method args from command_args
        _method_args = self.get_method_args(command_args, args,
                                        opt_args, default_args)
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

    def verify_move_jwt(self, src_realm, src_site, jwt):
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
            jwt_data = self.verify_move_jwt(src_realm, src_site, jwt)
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

        try:
            default_group = jwt_data['default_group']
        except KeyError:
            message = "JWT data misses default group."
            self.logger.warning(message)
            status = False
            return self.build_response(status, message)

        # Make sure new default group exists.
        result = backend.search(object_type="group",
                                attribute="name",
                                value=default_group,
                                realm=config.realm,
                                site=config.site,
                                return_type="instance")
        if not result:
            message = "Unknown group: %s" % default_group
            self.logger.warning(message)
            status = False
            return self.build_response(status, message)

        _default_group = result[0]
        if not _default_group.verify_acl("add:default_group_user"):
            message = "Failed to set new default group: %s" % default_group
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
                    backend.delete_object(x_src_oid)
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
                move_object.group = default_group
                move_object.update_extensions("site_move")
                move_object._write()
                moved_objects[x_src_oid.full_oid] = {}
                moved_objects[x_src_oid.full_oid]['uuid'] = move_object.uuid
                moved_objects[x_src_oid.full_oid]['dst'] = move_object.oid.full_oid
            elif x_src_oid.object_type == "token":
                try:
                    backend.delete_object(x_src_oid)
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

    def handle_backend_commands(self, backend_command, command_args):
        """ Handle 'backend' commands. """
        status = False
        response = ""

        valid_backend_commands = [  "search",
                                    "import",
                                    "restore",
                                    "get_oid",
                                    "get_uuid",
                                    "object_exists",
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

        if backend_command == "object_exists":
            status = True
            try:
                object_id = command_args['object_id']
            except:
                message = "MGMT_INCOMPLETE_COMMAND"
                status = False
                return self.build_response(status, message)

            object_id = oid.get(object_id=object_id)
            try:
                response = backend.object_exists(object_id)
            except Exception as e:
                response = ("Error checking if object exists: %s: %s"
                            % (object_id, e))
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
                                    target_method=backend.restore_object,
                                    args=args, command_args=command_args,
                                    process=True,
                                    thread=False)
            except Exception as e:
                config.raise_exception()
                response = ("Error running command: %s: %s"
                                % (backend_command, e))
                status = False

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

        if backend_command == "get_oid":
            try:
                object_uuid = command_args['object_uuid']
            except:
                message = "MGMT_INCOMPLETE_COMMAND"
                status = False
                return self.build_response(status, message)

            try:
                object_type = command_args['object_type']
            except:
                object_type = None

            try:
                response = backend.get_oid(object_uuid, object_type=object_type)
                status = True
            except Exception as e:
                response = "Error getting OID: %s: %s" % (object_uuid, e)
                status = False
                config.raise_exception()

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
                config.raise_exception()
                response = "Internal server error."
                msg = "Unhandled exception running search: %s" % e
                logger.critical(msg)

        return self.build_response(status, response)

    def _process(self, command, command_args):
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
            job_uuid = command_args['job_uuid']
            command_args.pop('job_uuid')
        except:
            job_uuid = None

        # If a job exists handle it.
        if job_uuid:
            # Get callbacks
            for i in dict(command_args):
                if not i.startswith("callback:"):
                    continue
                callbacks[i] = command_args[i]
                # Remove callback from command_args
                command_args.pop(i)

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

        # Handle backend commands.
        if command == "move_object":
            return self.move_object(command_args)

        # Handle backend commands.
        if command == "backend":
            return self.handle_backend_commands(subcommand, command_args)

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
            default_callback = config.get_callback()
            def delete_object(object_id, force=False, verbose_level=0,
                callback=default_callback, **kwargs):
                object_id = oid.get(object_id=object_id)
                if not backend.object_exists(object_id):
                    return callback.error("Object does not exist.")
                if not force:
                    ask = callback.ask("Delete object? ")
                    if str(ask).lower() != "y":
                        return callback.abort()
                try:
                    backend.delete_object(object_id)
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
                    args = {'object_id' : object_id}
                    try:
                        status, \
                        response = self.start_job(name="delete_object",
                                            target_method=delete_object,
                                            args=args, opt_args={},
                                            command_args=command_args,
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
                        response = backend.index_dump(object_id=object_id)
                        status = True
                    except Exception as e:
                        config.raise_exception()
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
                    if "/" in object_identifier:
                        x = oid.resolve_path(object_identifier,
                                            object_type=object_type)
                        object_name = x['name']
                        object_unit = x['unit']

                        if object_identifier.startswith("/"):
                            object_path = object_identifier
                    else:
                        object_name = object_identifier

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
                                get_default_unit = True
                                if config.auth_user:
                                    result = config.auth_user.get_policies(policy_type="defaultunits",
                                                                            return_type="instance")
                                    if result:
                                        default_units_policy = result[0]
                                        try:
                                            object_unit = default_units_policy.get_default_unit(object_type)
                                            get_default_unit = False
                                        except NoUnitFound:
                                            get_default_unit = True

                                if get_default_unit:
                                    try:
                                        object_unit = config.get_default_unit(object_type)
                                    except:
                                        pass

                    # Check if object name does contain invalid chars.
                    if oid.check_name(object_type, object_name):
                        result = None
                        attribute = "name"

                        # We need to search for existing tokens by rel_path.
                        if object_type == "token":
                            attribute = "rel_path"
                        # We need to search for existing scripts by rel_path.
                        if object_type == "script":
                            attribute = "rel_path"
                        # We need to search for existing units by rel_path.
                        if object_type == "unit":
                            attribute = "rel_path"

                        # Check if we can find the object on our site.
                        if object_type != "realm" and object_type != "site":
                            # Search for existing object of our own site.
                            try:
                                result = backend.search(object_type=object_type,
                                                        attribute=attribute,
                                                        value=object_name,
                                                        return_type="instance",
                                                        realm=config.realm,
                                                        site=config.site)
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

            # Merge method args from dict.
            try:
                try:
                    _args = command_map[x_type][object_status][subcommand]['args']
                except:
                    _args = command_map[object_type][object_status][subcommand]['args']
                for i in _args:
                    if i in args:
                        continue
                    # Try to get default value from method args.
                    try:
                        args[i] = command_map[x_type][object_status][subcommand]['args'][i]
                    except:
                        try:
                            args[i] = command_map[object_type][object_status][subcommand]['args'][i]
                        except:
                            args[i] = None
            except:
                pass

            try:
                try:
                    _opt_args = command_map[x_type][object_status][subcommand]['oargs']
                except:
                    _opt_args = command_map[object_type][object_status][subcommand]['oargs']
                for i in _opt_args:
                    if i in opt_args:
                        continue
                    opt_args[i] = None
            except:
                pass

            try:
                try:
                    default_args = command_map[x_type][object_status][subcommand]['dargs']
                except:
                    default_args = command_map[object_type][object_status][subcommand]['dargs']
            except:
                default_args = {}

            ## WARNING: enabling command_args debug output may contain passwords and other sensitive data!!
            #if config.debug_enabled and config.raise_exceptions:
            #    if command_args:
            #        _command_args = []
            #        for i in command_args:
            #            _command_args.append("%s=%s, " % (i, command_args[i]))
            #        logger.debug("Got command args: %s" % ", ".join(_command_args))

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
                _method_args = self.get_method_args(command_args, args,
                                                opt_args, default_args)
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
                                        args=args, opt_args=opt_args,
                                        default_args=default_args,
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
