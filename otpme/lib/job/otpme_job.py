# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time
import setproctitle

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except:
    pass

from otpme.lib import log
from otpme.lib import stuff
from otpme.lib import syslog
from otpme.lib import config
from otpme.lib import multiprocessing
from otpme.lib.job.callback import JobCallback
from otpme.lib.protocols.utils import send_job

from otpme.lib.exceptions import *

class OTPmeJob(object):
    """ Class to run a OTPme job as thread. """
    def __init__(self, name, target_method, thread=True, process=False,
        timeout=None, lock_timeout=30, lock_wait_timeout=0, client=None,
        reload_objects_on_change=True, _caller="API", args={}):
        # Set our name.
        self.name = name
        # Connected client.
        self.client = client
        # Gen job UUID.
        self.uuid = stuff.gen_uuid()
        # Generate uniq job ID.
        self.job_id = f"{self.uuid} ({self.name})"
        # Method and arguments.
        self.target_method = target_method
        self.args = args
        # Start job as thread.
        self.start_thread = thread
        # Start job as sub process.
        self.start_process = process
        # The job start time.
        self.start_time = None
        # Job timeout.
        self.timeout = timeout
        # Lock parameters.
        self.lock_timeout = lock_timeout
        self.lock_wait_timeout = lock_wait_timeout
        self.reload_objects_on_change = reload_objects_on_change
        self.pid = None
        # Our proctitle. Used when started as process and for the
        # multiprocessing manager.
        self.proctitle = "otpme-job"
        if config.add_job_id_to_proctitle:
            self.proctitle = f"{self.proctitle} JobID: {self.job_id}"
        else:
            self.proctitle = f"{self.proctitle} JobUUID: {self.uuid}"
        self.callback = None
        self.stopped = False
        self.exit_info = {}
        self.term_message = None
        self.return_value = None
        self._child = None
        self._child_joined = False
        self._caller = _caller
        self.objects_written = multiprocessing.get_bool(name="objects_written")
        self.logger = config.logger

    def __str__(self):
        return self.job_id

    def start(self):
        """ Start job.  """
        if self.start_thread or self.start_process:
            # Create shared object dict to hold job exit info.
            dict_id = f"{self.uuid}:exit_info"
            self.exit_info = multiprocessing.get_dict(dict_id)
            # Create queues for communication with jobs child thread.
            self.comm_queue = multiprocessing.InterProcessQueue()
            # Start job as new thread or process.
            self._start()
            # Send job UUID to client.
            job_reply = send_job(job_id=self.uuid,
                                realm=config.realm,
                                site=config.site)
            return True, job_reply
        else:
            job_reply = self.start_job()
            return job_reply

    def _start(self):
        """ Start the job as thread and manage callback communication. """
        log_msg = _("Starting job: {self.name}", log=True)[1]
        self.logger.debug(log_msg)

        # Start job as thread.
        log_msg = _("Job started: {job_name}", log=True)[1]
        log_msg = log_msg.format(job_name=self.name)
        if self.timeout is not None:
            log_msg = f"{log_msg} (tmo {self.timeout}s)"
        if self.start_thread:
            self._child = multiprocessing.start_thread(name=self.job_id,
                                                    target=self.start_job,
                                                    start=False,
                                                    daemon=True)
        # Start job as sub process.
        if self.start_process:
            self._child = multiprocessing.start_process(name=self.job_id,
                                                    target=self.start_job,
                                                    start=False)
        # Start child.
        self._child.start()

        if self.start_process:
            self.pid = self._child.pid
            log_msg = f"{log_msg} ({self._child.pid})"
        self.logger.debug(log_msg)

    def check_timeout(self):
        """ Check if job timeout has been reached. """
        if self.timeout is None:
            return False
        if self.start_time is None:
            return False
        job_age = time.time() - self.callback.last_used
        if job_age >= self.timeout:
            return True
        return False

    def handle_job_timeout(self):
        """ Handle job timeout. """
        while True:
            time.sleep(0.01)
            if not self.check_timeout():
                continue
            msg, log_msg = _("Job timed out: {job_id} ({timeout})", log=True)
            msg = msg.format(job_id=self.job_id, timeout=self.timeout)
            log_msg = log_msg.format(job_id=self.job_id, timeout=self.timeout)
            self.logger.warning(log_msg)
            self.callback.stop(False, msg, raise_exception=False)
            exit_message = _("Job '{job_name}' timed out.")
            exit_message = exit_message.format(job_name=self.name)
            # Set timeout info.
            self.exit_info['exit_status'] = False
            self.exit_info['exit_message'] = exit_message
            self.stop()
            break

    def start_job(self):
        """ This method finally starts the job. """
        from otpme.lib import cache
        job_status = True
        job_error = None
        job_reply = []
        job_log = []

        # Handle multiprocessing stuff.
        if self.start_process:
            def signal_handler(_signal, frame):
                """ Handle SIGTERM. """
                from otpme.lib import config
                # Get logger.
                logger = config.logger
                self.callback.stop_job = True
                if config.active_transactions:
                    msg, log_msg = _("Job not stoppable at this stage.", log=True)
                    self.callback.error(msg)
                    logger.warning(log_msg)
                    return
                if _signal == 15:
                    log_msg = _("Received SIGTERM.", log=True)[1]
                    logger.info(log_msg)
                    #self.close()
                    os._exit(0)

            multiprocessing.atfork(quiet=True,
                                exit_on_signal=True,
                                signal_method=signal_handler)
            setproctitle.setproctitle(self.proctitle)
            self.pid = os.getpid()
            # Reconfigure logger.
            #for h in self.logger.handlers:
            #    h.close()
            self.logger = log.setup_logger(pid=True,
                                existing_logger=config.logger)
            # Timeout handler.
            if self.timeout is not None:
                multiprocessing.start_thread(name=self.job_id,
                                            target=self.handle_job_timeout,
                                            daemon=True)

        # FIXME: make this thread safe (e.g. multiprocessing.add_job_uuid()).
        # Set job UUID (Used to inform clusterd about new objects to sync.)
        multiprocessing.job_uuid = self.uuid

        # Create job callback
        self.callback = JobCallback(name=self.name, job=self)
        # Add callback to target method args
        self.args['callback'] = self.callback
        # Set job start time.
        self.start_time = time.time()

        if config.debug_level("debug_profile") > 0:
            import pstats
            import cProfile
            profiler = cProfile.Profile()
            profiler.enable()

        # Start the job.
        # For methods with object lock decorator we force not to
        # wait for an existing lock.
        try:
            self.target_method.object_lock
            self.args['lock_timeout'] = self.lock_timeout
            self.args['lock_wait_timeout'] = self.lock_wait_timeout
            self.args['lock_reload_on_change'] = self.reload_objects_on_change
        except:
            pass
        try:
            job_status = self.target_method(**self.args)
            # If the job return failure try to get its last error.
            if job_status is False:
                try:
                    job_error = self.exit_info['last_error']
                except:
                    pass
        except OTPmeJobException as e:
            job_error = str(e)
            log_msg = job_error
            self.logger.warning(log_msg)
            job_reply.append(job_error)
            job_status = False
        except Exception as e:
            job_error, log_msg = _("Job error running command method: {method_name}: {error}", log=True)
            job_error = job_error.format(method_name=self.target_method.__name__, error=e)
            log_msg = log_msg.format(method_name=self.target_method.__name__, error=e)
            self.logger.warning(log_msg)
            job_reply.append(job_error)
            job_log.append(job_error)
            job_status = False
            config.raise_exception()

        if job_status:
            # Write changed objects. This also happens on cache.flush() but
            # it still makes sense to have callback.objects because we this
            # way we only flush caches if this job has changed any object.
            objects_written = self.callback.write_modified_objects()
            # Clear caches after saving objects. This will also write any
            # other changed (cached) objects.
            if objects_written:
                cache.flush()
        else:
            # Make sure all locks are released.
            self.callback.release_cache_locks()
            # Clear caches.
            cache.flush(commit=False)

        # In debug mode we also send the job log to the client.
        if config.debug_enabled:
            job_reply += job_log

        # Reply needs to be a string when sending to a client.
        if self._caller == "CLIENT":
            job_reply = "\n".join(job_reply)
        else:
            job_reply = self.return_value

        if not job_error:
            job_error = "Job failed for unknown reason."

        if job_status:
            log_msg = _("Job finished successful: {name}", log=True)[1]
            log_msg = log_msg.format(name=self.name)
            self.logger.debug(log_msg)
        elif job_status is None:
            log_msg = _("Job aborted: {job_name}", log=True)[1]
            log_msg = log_msg.format(job_name=self.name)
            self.logger.debug(log_msg)
        else:
            log_msg = _("Job failed: {job_name}: {error}", log=True)[1]
            log_msg = log_msg.format(job_name=self.name, error=job_error)
            self.logger.debug(log_msg)

        # Print job timings.
        if config.print_timing_results and config.daemon_mode:
            from otpme.lib import debug
            debug.print_timing_result(print_status=True)

        if config.debug_level("debug_profile") > 0:
            profiler.disable()
            sort_by = config.debug_profile_sort
            stats = pstats.Stats(profiler).sort_stats(sort_by)
            stats.print_stats(10)

        # Do some cleanup.
        if self.start_process:
            multiprocessing.cleanup()

        # Reset job UUID.
        multiprocessing.job_uuid = None

        if self.callback:
            return self.callback.stop(job_status, job_reply)

        return job_status, job_reply

    def job_is_alive(self):
        """ Check if job thread/process is alive. """
        if self.start_thread:
            try:
                return self._child.is_alive()
            except:
                return False
        if self.start_process:
            try:
                return self._child.is_alive()
            except:
                return False

    def is_alive(self):
        """ Check child proceess status. """
        if self.job_is_alive():
            return True
        return False

    def stop(self, signal=15):
        """ Stop job. """
        if self.stopped:
            return
        self.stopped = True
        if not self.start_process:
            msg = _("Only jobs that run as process are stoppable.")
            raise JobNotStoppable(msg)
        if not self.job_is_alive():
            return
        # Terminate job process.
        if self._child is not None:
            log_msg = _("Sending signal to job: {job_name}", log=True)[1]
            log_msg = log_msg.format(job_name=self.name)
            self.logger.info(log_msg)
            try:
                stuff.kill_pid(self._child.pid, signal=signal)
            except Exception as e:
                config.raise_exception()
            while self.job_is_alive():
                time.sleep(0.01)
        log_msg = _("Job stopped: {job_name}", log=True)[1]
        log_msg = log_msg.format(job_name=self.name)
        self.logger.debug(log_msg)

        # Check if job finished before we could terminate it.
        if 'exit_status' in self.exit_info:
            return False
        exit_message = _("Job '{job_name}' aborted on user request.")
        exit_message = exit_message.format(job_name=self.name)
        # Set aborted info.
        self.exit_info['exit_status'] = False
        self.exit_info['exit_message'] = exit_message
        # Wakeup mgmtd waiting for new job messages/queries.
        comm_handler = self.comm_queue.get_handler("job")
        try:
            comm_handler.send(recipient="client", command="job_end", timeout=1)
        except QueueClosed:
            pass
        except ExitOnSignal:
            pass
        return True

    def join(self):
        """ Stop multiprocessing manager and join job thread/process. """
        if not self.start_process:
            return
        if self._child_joined:
            return
        # Join child thread/process.
        if not self._child:
            return
        self._child_joined = True
        self._child.join()

    def close(self):
        # Join child process/thread.
        self.join()
        self.exit_info.clear()
        self.comm_queue.close()
        self.comm_queue.unlink()
        self.objects_written.close()
        if self.start_thread:
            syslog.close_log_handlers()

