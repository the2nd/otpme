# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
#import sys
import time
import signal
import psutil
import random

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except:
    pass

from otpme.lib import srp
from otpme.lib import stuff
from otpme.lib import cache
from otpme.lib import config
from otpme.lib import locking
from otpme.lib import filetools
from otpme.lib import otpme_pass
from otpme.lib import init_otpme
from otpme.lib import connections
from otpme.lib import multiprocessing
from otpme.lib.fuse import get_mount_point
from otpme.lib.protocols import status_codes
#from otpme.lib.messages import error_message
from otpme.lib.register import register_module
from otpme.lib.socket.listen import ListenSocket
from otpme.lib.offline_token import OfflineToken
from otpme.lib.multiprocessing import start_thread
from otpme.lib.daemon.unix_daemon import UnixDaemon
from otpme.lib.multiprocessing import get_sync_manager
from otpme.lib.classes.conn_handler import ConnHandler
from otpme.lib.socket.handler import SocketProtoHandler

from otpme.lib.exceptions import *

CONN_LOCK_TYPE = "agent.connection"

multiprocessing.register()
locking.register_lock_type(CONN_LOCK_TYPE, module=__file__)

class OTPmeAgent(UnixDaemon):
    """ OTPme agent. """
    def __init__(self, pidfile=None, user=None):
        # Get system user if none was given.
        if not user:
            user = config.system_user()
        # Get pidfile path
        if not pidfile:
            pidfile = config.get_agent_pidfile(user)
        # Set our name.
        self.name = "agent"
        # Set user we run as.
        self.user = user
        self.pid = None
        # Set PID file.
        self.pidfile = pidfile
        # Get logger
        self.logger = config.logger
        # Logfile we will write log messages to.
        self.logfile = None
        # Rotate logfile if it exceeds this size (kb).
        self.logfile_rotate_size = 1024
        # Remove old logfiles if more than logfile_max_rotate exist.
        self.logfile_max_rotate = 10
        # Create users agent config dir/file
        self.create_conf_file()
        # Time in seconds after agent will shutdown if its idle
        self.idle_timeout = 300
        # Get timeout values from config (default
        # or overridden via command line switch).
        self.connect_timeout = config.connect_timeout
        self.timeout = config.connection_timeout
        # Indicates that there is an ongoing config reload
        self.loading = False
        # Indicates that we received config reload command (e.g. SIGHUP)
        self.config_reload = False
        # Create shared object dict to hold login session ID to PID mapping.
        self.session_ids = {}
        # Create shared object dict to hold login session data.
        self.login_sessions = {}
        # Create dict to hold daemon connections for all login sessions.
        self.connections = {}
        self.comm_queue = None
        # Call parent class init to init UnixDaemon
        super(OTPmeAgent, self).__init__("otpme-agent", pidfile)

    def signal_handler(self, _signal, frame):
        """ Handle signals. """
        if os.getpid() != self.pid:
            return

        if _signal == 2:
            log_msg = _("Exiting on Ctrl+C", log=True)[1]
            self.logger.warning(log_msg)

        if _signal == 15:
            log_msg = _("Exiting on 'SIGTERM'.", log=True)[1]
            self.logger.warning(log_msg)

        if _signal == 1:
            log_msg = _("Received 'SIGHUP'.", log=True)[1]
            self.logger.warning(log_msg)
            if not self.loading:
                # Flush method caches.
                cache.flush()
                # Clear cache.
                cache.clear()
                # Notify ourselves about reload
                self.config_reload = True
            return

        log_msg = _("Received quit, terminating.", log=True)[1]
        self.logger.info(log_msg)

        # Get user sessions.
        try:
            sessions = dict(self.login_sessions)
        except:
            sessions = {}
        # Close user all sessions (e.g. logout).
        for login_pid in sessions:
            self.close_user_sessions(login_pid)

        # Close all sockets.
        self.close_all_sockets()

        # Handle multiprocessing stuff.
        multiprocessing.cleanup()

        # Remove IPC queue.
        if self.comm_queue:
            try:
                self.comm_queue.close()
            except Exception as e:
                log_msg = _("Failed to close comm queue: {comm_queue}: {error}", log=True)[1]
                log_msg = log_msg.format(comm_queue=self.comm_queue, error=e)
                self.logger.critical(log_msg)
            try:
                self.comm_queue.unlink()
            except Exception as e:
                log_msg = _("Failed to unlink comm queue: {comm_queue}: {error}", log=True)[1]
                log_msg = log_msg.format(comm_queue=self.comm_queue, error=e)
                self.logger.critical(log_msg)

        # Shutdown multiprocessing manager.
        multiprocessing.manager.shutdown()

        if os.path.exists(self.pidfile):
            os.remove(self.pidfile)
        try:
            self._shutdown.close()
        except Exception as e:
            log_msg = _("Failed to close shared bool: {shutdown_name}", log=True)[1]
            log_msg = log_msg.format(shutdown_name=self._shutdown.name)
            self.logger.critical(log_msg)

        # Finally exit.
        os._exit(0)

    @property
    def shutdown(self):
        return self._shutdown.value

    @shutdown.setter
    def shutdown(self, new_status):
        self._shutdown.value = new_status

    def configure(self):
        """ Make sure we are configured correctly """
        # Enable file logging if not in debug mode
        if not config.debug_enabled:
            config.file_logging = True
        # Read agent config file to re-configure logger etc.
        self.read_conf_file()

    def get_conf_file(self):
        """ Get path to users config file """
        conf_dir = config.get_user_conf_dir(config.system_user())
        conf_file = f"{conf_dir}/otpme-agent.conf"
        return conf_file

    def create_conf_file(self):
        """ Create agent config file in users home directory """
        username = config.system_user()
        user_home = os.path.expanduser(f"~{username}")
        if not os.path.exists(user_home):
            return
        # Make sure user specific config file exists.
        config.ensure_user_conf_file()
        agent_conf_file = self.get_conf_file()
        # Make sure otpme-agent config exists.
        if not os.path.exists(agent_conf_file):
            log_msg = _("Creating config file: {config_file}", log=True)[1]
            log_msg = log_msg.format(config_file=agent_conf_file)
            self.logger.debug(log_msg)
            fd = open(agent_conf_file, "w")
            fd.write('#LOGFILE="~/.otpme/otpme-agent.log"\n')
            fd.write('#LOGLEVEL="DEBUG"\n')
            fd.write('#LOGFILE_ROTATE_SIZE="1024"\n')
            fd.write('#LOGFILE_MAX_ROTATE="10"\n')
            fd.write('#IDLE_TIMEOUT="30"\n')
            fd.close()
        files = {
                agent_conf_file : 0o600,
                }
        filetools.ensure_fs_permissions(files=files,
                                        user=username,
                                        group=True)

    def read_conf_file(self):
        """ Read agent config file. """
        agent_conf_file = self.get_conf_file()
        if not os.path.exists(agent_conf_file):
            return
        log_msg = _("Loading config file: {config_file}", log=True)[1]
        log_msg = log_msg.format(config_file=agent_conf_file)
        self.logger.info(log_msg)

        try:
            # Open config file for reading.
            fd = open(agent_conf_file, 'r')
        except (OSError, IOError) as error:
            msg = _("Error reading config file: {error}")
            msg = msg.format(error=error)
            raise Exception(msg)

        # Read complete file.
        file_content = fd.read()
        fd.close()
        # Load config data.
        conf = stuff.conf_to_dict(file_content)

        try:
            self.idle_timeout = conf['IDLE_TIMEOUT']
        except KeyError:
            pass

        if not config.debug_enabled:
            # Try to read loglevel from config.
            try:
                config.loglevel = conf['LOGLEVEL']
            except:
                pass
            # Try to read logfile max size from config.
            try:
                self.logfile_rotate_size = int(conf['LOGFILE_ROTATE_SIZE'])
            except:
                pass
            # Try to read logfile max rotate from config.
            try:
                self.logfile_max_rotate = int(conf['LOGFILE_MAX_ROTATE'])
            except:
                pass
            # Try to read logfile from config and re-configure logger.
            try:
                self.logfile = conf['LOGFILE']
                self.logfile = os.path.expanduser(self.logfile)
            except:
                self.logfile = None
            # Re-configure logger.
            self.configure_logger()

    def build_lock_id(self, login_pid, realm, site):
        """ Build lock ID. """
        lock_id = f"agent:connection:{login_pid}:{realm}:{site}"
        return lock_id

    def acquire_connection_lock(self, login_pid, realm, site):
        """ Acquire connection lock. """
        lock_id = self.build_lock_id(login_pid, realm, site)
        conn_lock = locking.acquire_lock(lock_type=CONN_LOCK_TYPE,
                                            lock_id=lock_id)
        return conn_lock

    def configure_logger(self):
        """ Try to (re)configure logger """
        if not self.logfile:
            return
        try:
            self.logger = config.setup_logger(log_file=self.logfile,
                                        existing_logger=config.logger)
        except Exception as e:
            log_msg = _("Failed to log to file: {logfile}: {error}", log=True)[1]
            log_msg = log_msg.format(logfile=self.logfile, error=e)
            self.logger.warning(log_msg)

    def wait_for_pid(self, login_pid):
        """ Wait until PID ends and send event to agent main process. """
        if login_pid in self.watch_pids:
            return
        # FIXME: If its possible to get an "PID ended" event in python we
        #        should use it here instead of polling!
        try:
            proc = psutil.Process(int(login_pid))
        except Exception as e:
            log_msg = _("Failed to watch PID: {pid}: {error}", log=True)[1]
            log_msg = log_msg.format(pid=login_pid, error=e)
            self.logger.warning(log_msg)
            return
        self.watch_pids.append(login_pid)
        log_msg = _("Started watching PID with login session: {pid}", log=True)[1]
        log_msg = log_msg.format(pid=login_pid)
        self.logger.debug(log_msg)
        while proc.is_running():
            try:
                proc.wait(timeout=2)
            except psutil.TimeoutExpired:
                pass
            if not proc.is_running():
                pid_end_command = f"pid_ended {login_pid}"
                comm_handler = self.comm_queue.get_handler("wait_for_pid")
                comm_handler.send(recipient="main_process",
                                    command=pid_end_command,
                                    timeout=1)
                comm_handler.close()
            if not login_pid in self.login_sessions:
                log_msg = _("Stopped watching PID with no more login sessions: {pid}", log=True)[1]
                log_msg = log_msg.format(pid=login_pid)
                self.logger.debug(log_msg)
                break
        try:
            self.watch_pids.remove(login_pid)
        except:
            pass

    def remove_offline_rsp(self, login_user, session_id):
        """ Try to remove offline RSP. """
        # If this session is not from the current system
        # user we can not remove the login session file.
        if login_user != config.system_user():
            return
        log_msg = _("Removing offline session...", log=True)[1]
        self.logger.debug(log_msg)
        # Try to remove offline RSP.
        try:
            # Get offline token handler.
            offline_token = OfflineToken()
            # Set user.
            offline_token.set_user(login_user)
            # Acquire offline token lock
            offline_token.lock()
            # Try to remove on-disk RSP/session.
            offline_token.remove_session(session_id)
        except NoOfflineSessionFound as e:
            log_msg = str(e)
            self.logger.debug(log_msg)
        except Exception as e:
            log_msg = str(e)
            self.logger.critical(log_msg)
        finally:
            # Release offline token lock
            offline_token.unlock()

    def remove_outdated_session_dirs(self):
        """ Remove outdated session directories. """
        # Get system user.
        username = config.system_user()
        try:
            # Get offline token handler.
            offline_token = OfflineToken()
            # Set user.
            offline_token.set_user(username)
            # Acquire offline token lock
            offline_token.lock()
            # Remove outdated session dirs.
            offline_token.remove_outdated_session_dirs()
            # Release offline token lock
            offline_token.unlock()
        except Exception as e:
            # Release offline token lock
            offline_token.unlock()
            log_msg = _("Error removing outdated session directories: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            self.logger.critical(log_msg)

    def close_user_sessions(self, login_pid):
        """ Close all user sessions. """
        # Get all server sessions of login_pid.
        try:
            agent_sessions = dict(self.login_sessions)
            server_sessions = agent_sessions[login_pid]['server_sessions']
        except:
            server_sessions = {}
        # Remove realm login sessions.
        for realm in dict(server_sessions):
            for site in dict(server_sessions[realm]):
                # Check if session is logged in.
                try:
                    rsp = server_sessions[realm][site]['rsp']
                except:
                    rsp = None

                # Get offline flag.
                try:
                    offline = server_sessions[realm][site]['offline']
                except:
                    # Default should be to send logout command.
                    offline = False

                # If session is logged in try to logout user.
                if rsp and not offline:
                    log_msg = _("Login process '{pid}' ended. Trying to logout user.", log=True)[1]
                    log_msg = log_msg.format(pid=login_pid)
                    self.logger.info(log_msg)
                    try:
                        self.logout_user(login_pid, realm, site)
                    except Exception as e:
                        log_msg = _("Failed to logout user: {error}", log=True)[1]
                        log_msg = log_msg.format(error=e)
                        self.logger.warning(log_msg)
                    continue

                if rsp and offline:
                    log_msg = _("Login process '{pid}' ended. Not sending logout command for offline session.", log=True)[1]
                    log_msg = log_msg.format(pid=login_pid)
                    self.logger.info(log_msg)
                    continue

        for login_pid in agent_sessions:
            # Umount shares on agent shutdown.
            session = agent_sessions[login_pid]
            login_user = agent_sessions[login_pid]['login_user']
            try:
                shares = session['mounted_shares']
            except KeyError:
                shares = []
            messages = []
            umounted_shares = []
            for share_id in shares:
                share_name = shares[share_id]['name']
                share_site = shares[share_id]['site']
                mount_point = get_mount_point(login_user, share_site, share_name)
                try:
                    os.system(f"fusermount -u {mount_point}")
                except Exception as e:
                    try:
                        os.system(f"fusermount -z -u {mount_point}")
                    except Exception as e:
                        log_msg = _("Failed to unmount share: {mount_point}: {error}", log=True)[1]
                        log_msg = log_msg.format(mount_point=mount_point, error=e)
                        messages.append(log_msg)
                        self.logger.warning(log_msg)
                try:
                    os.rmdir(mount_point)
                except Exception as e:
                    log_msg = _("Failed to rmdir mountpoint: {mount_point}: {error}", log=True)[1]
                    log_msg = log_msg.format(mount_point=mount_point, error=e)
                    self.logger.warning(log_msg)
                umounted_shares.append(share_id)
            if umounted_shares:
                log_msg = _("Shares unmounted: {shares}", log=True)[1]
                log_msg = log_msg.format(shares=umounted_shares)
                self.logger.info(log_msg)

        log_msg = _("Login process '{pid}' ended. Removing empty session.", log=True)[1]
        log_msg = log_msg.format(pid=login_pid)
        self.logger.info(log_msg)

        # Close daemon connections.
        self.close_user_conns(login_pid)
        # Delete session.
        self.delete_session(login_pid)
        # Remove old session dirs.
        if not stuff.check_pid(login_pid):
            self.remove_outdated_session_dirs()

    def close_user_conns(self, login_pid):
        """ Try to close all connections for given login_pid (user). """
        try:
            login_user = self.login_sessions[login_pid]['login_user']
            login_pid_conns = self.connections[login_pid]
        except:
            login_pid_conns = {}

        if len(login_pid_conns) > 0:
            log_msg = _("Closing daemon connections for user '{user}'.", log=True)[1]
            log_msg = log_msg.format(user=login_user)
            self.logger.info(log_msg)

        for realm in dict(login_pid_conns):
            for site in dict(login_pid_conns[realm]):
                for daemon in dict(login_pid_conns[realm][site]):
                    # Use try/pass as dict may be changed by _conn_proxy()
                    # thread while we are running.
                    try:
                        log_msg = _("Closing connection to '{realm}/{site}/{daemon}'.", log=True)[1]
                        log_msg = log_msg.format(realm=realm, site=site, daemon=daemon)
                        self.logger.info(log_msg)
                        self.close_daemon_conn(realm, site, daemon, login_pid)
                    except:
                        pass

    def get_next_reneg(self, login_pid, realm, site):
        """ Return seconds until next renegotiation. """
        # FIXME: read this from config file!!?!
        # Minimum time in minutes between session renegotiations. This may be
        # needed to e.g. get a notebook thats only online for short time periods
        # to renegotiate successful.
        agent_reneg_min_interval = 180
        # Retry interval in seconds for failed renegotiations.
        agent_failed_reneg_retry = 120
        # Try to get session
        try:
            session = self.login_sessions[login_pid]['server_sessions'][realm][site]
        except:
            log_msg = _("Session does not exist anymore. Cannot calculate reneg: {pid}", log=True)[1]
            log_msg = log_msg.format(pid=login_pid)
            self.logger.debug(log_msg)
            return

        # Get session values
        login_time = session['login_time']
        session_timeout = session['session_timeout']
        session_unused_timeout = session['session_unused_timeout']
        next_reneg = session['next_reneg']
        next_retry = session['next_retry']
        last_reneg = session['last_reneg']
        last_failed_reneg = session['last_failed_reneg']

        if last_failed_reneg:
            # If we already have a next retry time use it.
            if next_retry is not None:
                return next_retry
            reneg_retry_interval = random.randint(0,agent_failed_reneg_retry)
            next_retry = time.time() + reneg_retry_interval
            # Reset reneg timer.
            next_reneg = None
        else:
            # If we already have a next reneg time use it.
            if next_reneg is not None:
                return next_reneg
            # Calculate session age in seconds.
            session_age = time.time() - login_time
            # Calculate remaining session lifetime in seconds.
            session_time_left = (session_timeout * 60) - session_age
            # Calculate time since last reneg in seconds.
            reneg_age = time.time() - last_reneg

            # If the remaining session lifetime is lower than the session unused
            # timeout we will use the remaining time to calculate the next reneg
            # interval.
            if session_time_left < (session_unused_timeout * 60):
                range_end = session_time_left
            else:
                range_end = session_unused_timeout

            # If the range end we selected above is higher than
            # agent_reneg_min_interval we replace it.
            if range_end > (agent_reneg_min_interval * 60):
                range_end = agent_reneg_min_interval * 60

            # We choose a random renegotiation interval to make it harder to
            # predict the new RSP (e.g. if someone was able to steal the
            # current/old RSP).
            agent_reneg_interval = random.randint(0,range_end)

            if reneg_age > agent_reneg_interval:
                next_reneg = time.time()
            else:
                seconds_unitl_reneg = agent_reneg_interval - reneg_age
                next_reneg = time.time() + seconds_unitl_reneg
            # Reset retry timer.
            next_retry = None

        # Update timestamps.
        session['next_reneg'] = next_reneg
        session['next_retry'] = next_retry

        # Update Session.
        try:
            login_session = self.login_sessions[login_pid]
            login_session['server_sessions'][realm][site] = session
            self.login_sessions[login_pid] = login_session
        except KeyError:
            log_msg = _("Session does not exist anymore. Cannot update reneg: {pid}", log=True)[1]
            log_msg = log_msg.format(pid=login_pid)
            self.logger.debug(log_msg)
            return

        # Return time for next reneg/try.
        if last_failed_reneg:
            return next_retry
        else:
            return next_reneg

    def reneg_session(self, login_pid, realm, site):
        """ Try to renegotiate session. """
        # Make sure no other connections is used while doing reneg.
        conn_lock = self.acquire_connection_lock(login_pid, realm, site)
        try:
            result = self._reneg_session(login_pid, realm, site)
        finally:
            # Release lock.
            conn_lock.release_lock()
        return result

    def _reneg_session(self, login_pid, realm, site):
        auth_conn = None
        try_update = True
        update_status = False

        # Try to get server session to reneg.
        if not login_pid in self.login_sessions:
            log_msg = _("Login session does not exists. Cannot renegotiate: {pid}", log=True)[1]
            log_msg = log_msg.format(pid=login_pid)
            self.logger.debug(log_msg)
            raise Exception(log_msg)

        try:
            session = self.login_sessions[login_pid]['server_sessions'][realm][site]
        except:
            log_msg = _("Session does not exists. Cannot renegotiate: {realm}/{site}", log=True)[1]
            log_msg = log_msg.format(realm=realm, site=site)
            self.logger.debug(log_msg)
            raise Exception(log_msg)

        # Get session values
        session_id = self.login_sessions[login_pid]['session_id']
        login_user = self.login_sessions[login_pid]['login_user']
        login_time = session['login_time']
        rsp = session['rsp']
        slp = session['slp']
        session_age = time.time() - login_time
        session_timeout = session['session_timeout']
        session_unused_timeout = session['session_unused_timeout']
        last_reneg = session['last_reneg']
        reneg_age = time.time() - last_reneg

        # Get session key to encrypt new RSP.
        session_key = session['session_key']

        # Try to update session.
        log_msg = _("Trying to renegotiate session for user: {user}", log=True)[1]
        log_msg = log_msg.format(user=login_user)
        self.logger.debug(log_msg)
        try:
            auth_conn = connections.get(daemon="authd", realm=realm, site=site,
                                        connect_timeout=self.connect_timeout,
                                        timeout=config.reneg_timeout, endpoint=False,
                                        use_agent=False, username=login_user,
                                        autoconnect=True, auto_auth=False,
                                        allow_untrusted=True, sync_token_data=False,
                                        reneg=True, rsp=rsp)
        except Exception as e:
            log_msg = _("Error getting daemon connection for session renegotiation: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            self.logger.warning(log_msg)
            update_message = log_msg
            try_update = False

        if try_update:
            try:
                update_message = auth_conn.authenticate()
                update_status = True
            except AuthFailed as e:
                log_msg = _("Authentication failed while doing session renegotiation: {error}", log=True)[1]
                log_msg = log_msg.format(error=e)
                self.logger.warning(log_msg)
                update_message = log_msg
                update_status = None
            except Exception as e:
                update_message = str(e)
                update_status = False

        if update_status:
            # Get new RSP from update message.
            new_rsp = auth_conn.new_rsp
            rsp_hash = otpme_pass.gen_one_iter_hash(login_user, new_rsp)
            # Gen SRP.
            new_srp = srp.gen(rsp_hash)
            # Update session auth data.
            session['rsp'] = new_rsp
            session['srp'] = new_srp
            # Update timestamps.
            session['next_reneg'] = None
            session['next_retry'] = None
            session['last_reneg'] = time.time()
            session['last_failed_reneg'] = None
            # If this session is from the current system user
            # we can try to update the login session file.
            if login_user == config.system_user():
                try:
                    # Get offline token handler.
                    offline_token = OfflineToken()
                    # Set user.
                    offline_token.set_user(login_user)
                    # Acquire offline token lock.
                    offline_token.lock()
                    # Try to update on-disk RSP/session for use with offline tokens.
                    if offline_token.save_rsp(session_id=session_id,
                                            realm=realm,
                                            site=site,
                                            rsp=new_rsp,
                                            slp=slp,
                                            session_key=session_key,
                                            update=True) is None:
                        log_msg = _("No offline session to update found.", log=True)[1]
                        self.logger.debug(log_msg)
                except Exception as e:
                    log_msg = _("Error updating RSP for use with offline tokens: {error}", log=True)[1]
                    log_msg = log_msg.format(error=e)
                    self.logger.critical(log_msg)
                finally:
                    # Release offline token lock.
                    offline_token.unlock()
        elif update_status is False:
            # Update failed timestamp.
            session['last_failed_reneg'] = time.time()
            # Update session retry timer.
            session['next_retry'] = None

            if session_age > (session_timeout * 60):
                log_msg = _("Session renegotiation failed and session timeout ({timeout} min.) reached.", log=True)[1]
                log_msg = log_msg.format(timeout=session_timeout)
                self.logger.warning(log_msg)
                update_status = None
            else:
                if reneg_age > session_unused_timeout * 60:
                    log_msg = _("Session renegotiation failed and session unused timeout ({timeout} min.) reached.", log=True)[1]
                    log_msg = log_msg.format(timeout=session_unused_timeout)
                    self.logger.warning(log_msg)
                    update_status = None
                else:
                    log_msg = _("Session renegotiation failed: {message}", log=True)[1]
                    log_msg = log_msg.format(message=update_message)
                    self.logger.warning(log_msg)

        # Close auth connection.
        if auth_conn:
            auth_conn.close()

        # If our (server) session does not exist anymore delete agent session.
        if update_status is None:
            self.delete_session(login_pid, force=True, realm=realm, site=site)
            # Try to remove on-disk RSP/session.
            self.remove_offline_rsp(login_user, session_id)
        else:
            # Update Session.
            try:
                login_session = self.login_sessions[login_pid]
                login_session['server_sessions'][realm][site] = session
                self.login_sessions[login_pid] = login_session
            except:
                update_message = _("Failed to update agent login session.")
                update_status = False

        if update_status is False:
            raise Exception(update_message)

        return update_status

    def logout_user(self, login_pid, realm=None, site=None):
        """ Try to logout given login_pid (user). """
        # If we got no realm/site logout all sessions.
        if not realm:
            msg = None
            # Get all server sessions of login_pid.
            try:
                server_sessions = self.login_sessions[login_pid]['server_sessions']
            except:
                server_sessions = {}
            exception = None
            for realm in dict(server_sessions):
                for site in dict(server_sessions[realm]):
                    try:
                        msg = self.logout_user(login_pid, realm, site)
                    except Exception as e:
                        exception = e
            if exception:
                raise exception
            return msg

        # Close all connections for the given user.
        self.close_user_conns(login_pid)

        # Try to get session data.
        try:
            session_id = self.login_sessions[login_pid]['session_id']
            login_user = self.login_sessions[login_pid]['login_user']
            slp = self.login_sessions[login_pid]['server_sessions'][realm][site]['slp']
        except:
            return

        # FIXME: Should we walk through all sessions and check if ssh_agent_pid is used by other session and if not kill agent and remove session??!

        # Try to logout user.
        log_msg = _("Trying to logout user: {user}", log=True)[1]
        log_msg = log_msg.format(user=login_user)
        self.logger.info(log_msg)

        # Get connection to authd and logout.
        while True:
            try:
                auth_conn = connections.get(daemon="authd",
                                            username=login_user,
                                            realm=realm,
                                            site=site,
                                            slp=slp,
                                            login=False,
                                            logout=True,
                                            use_agent=False,
                                            auto_auth=False,
                                            autoconnect=True,
                                            allow_untrusted=True,
                                            connect_timeout=self.connect_timeout,
                                            timeout=self.timeout, endpoint=False)
            except ConnectionError:
                time.sleep(0.01)
                continue
            except Exception as e:
                msg = _("Error connecting to auth daemon to logout: {e}")
                msg = msg.format(e=e)
                raise OTPmeException(msg)
            else:
                break

        # Send logout command.
        try:
            logout_message = auth_conn.authenticate()
            if logout_message:
                log_msg = _("User logged out successfully: {realm}/{site}", log=True)[1]
                log_msg = log_msg.format(realm=realm, site=site)
                self.logger.info(log_msg)
                # Try to remove on-disk RSP/session.
                self.remove_offline_rsp(login_user, session_id)
                return logout_message
            else:
                log_msg = _("User logout failed", log=True)[1]
                self.logger.critical(log_msg)
                msg = _("User logout failed: {message}")
                msg = msg.format(message=logout_message)
                raise OTPmeException(msg)
        except Exception as e:
            log_msg = _("Error while sending logout request: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            self.logger.warning(log_msg)
        finally:
            auth_conn.close()

    def delete_session(self, login_pid, force=False, realm=None, site=None):
        """ Delete user session. """
        # Try to get session.
        try:
            session = self.login_sessions[login_pid]
        except KeyError:
            return
        # Try to get username from session.
        try:
            login_user = session['login_user']
        except KeyError:
            return
        # Try to get session ID.
        try:
            session_id = session['session_id']
        except KeyError:
            session_id = None

        # Get all server sessions of login_pid.
        try:
            server_sessions = session['server_sessions']
        except:
            server_sessions = {}

        if realm and site:
            log_msg = _("Removing session for user '{user}: {realm}/{site}", log=True)[1]
            log_msg = log_msg.format(user=login_user, realm=realm, site=site)
            self.logger.info(log_msg)
            if not force:
                # Wait until session is not in use anymore.
                conn_lock = self.acquire_connection_lock(login_pid, realm, site)
            # Remove server session.
            try:
                server_sessions[realm].pop(site)
            except KeyError:
                pass
            finally:
                if not force:
                    conn_lock.release_lock()
            # Update session.
            session['server_sessions'] = server_sessions
            self.login_sessions[login_pid] = session

            return

        log_msg = _("Removing session for user '{user}'.", log=True)[1]
        log_msg = log_msg.format(user=login_user)
        self.logger.info(log_msg)

        for realm in dict(server_sessions):
            for site in dict(server_sessions[realm]):
                if not force:
                    # Wait until session is not in use anymore.
                    conn_lock = self.acquire_connection_lock(login_pid, realm, site)
                # Remove server session.
                try:
                    server_sessions[realm].pop(site)
                except KeyError:
                    pass
                finally:
                    if not force:
                        conn_lock.release_lock()
            # Remove realm.
            try:
                server_sessions.pop(realm)
            except:
                pass

        # Delete session ID.
        try:
            self.session_ids.pop(session_id)
        except:
            pass
        # Delete session from dict.
        try:
            self.login_sessions.pop(login_pid)
        except:
            pass

        # Always remove connections dict.
        try:
            self.connections.pop(login_pid)
        except:
            pass

    def get_jwt(self, login_pid, challenge, use_dns=None):
        """ Request JWT for the given login session. """
        login_user = self.login_sessions[login_pid]['login_user']
        login_realm = self.login_sessions[login_pid]['realm']
        login_site = self.login_sessions[login_pid]['site']

        daemon = "authd"
        log_msg = _("Requesting JWT for cross-site authentication: {realm}/{site}/{user}", log=True)[1]
        log_msg = log_msg.format(realm=login_realm, site=login_site, user=login_user)
        self.logger.debug(log_msg)

        try:
            authd_conn = self.get_daemon_conn(realm=login_realm,
                                            site=login_site,
                                            daemon=daemon,
                                            login_pid=login_pid,
                                            use_dns=use_dns)
        except AuthFailed as e:
            log_msg = _("Authentication failed while sending requesting JWT: '{daemon}'. Closing connection...", log=True)[1]
            log_msg = log_msg.format(daemon=daemon)
            self.logger.warning(log_msg)
            self.close_daemon_conn(login_realm, login_site, daemon, login_pid)
            return
        except Exception as e:
            log_msg = _("Unable to request JWT from '{realm}/{site}/{daemon}: {error}", log=True)[1]
            log_msg = log_msg.format(realm=login_realm, site=login_site, daemon=daemon, error=e)
            self.logger.error(log_msg, exc_info=True)
            return
        command = "get_jwt"
        command_args = {}
        command_args['jwt_reason'] = "REALM_LOGIN"
        command_args['jwt_challenge'] = challenge
        command_args['jwt_accessgroup'] = config.realm_access_group
        # Send command.
        try:
            status, \
            status_code, \
            reply, \
            binary_data = authd_conn.send(command, command_args)
        except Exception as e:
            msg = _("Error requesting JWT: {e}")
            msg = msg.format(e=e)
            raise OTPmeException(msg)
        finally:
            # Release daemon connection.
            self.release_daemon_conn(realm=login_realm,
                                    site=login_site,
                                    daemon=daemon,
                                    login_pid=login_pid)
        if not status:
            msg = "Method to get JWT failed"
            if reply:
                msg = f"{msg}: {reply}"
            else:
                msg = f"{msg}."
            raise Exception(msg)
        return reply

    def login_user(self, login_pid, realm, site, use_dns=None):
        """ Login user to realm/site using JWT challenge/response. """
        from otpme.lib.classes.login_handler import LoginHandler
        login_session = self.login_sessions[login_pid]
        login_user = login_session['login_user']
        login_realm = login_session['realm']
        login_site = login_session['site']
        #offline = login_session['server_sessions']
        #offline = offline[login_realm][login_site]['offline']
        try:
            server_sessions = login_session['server_sessions']
            server_session = server_sessions[login_realm][login_site]
        except:
            log_msg = _("Session does not exists. Cannot renegotiate: {realm}/{site}", log=True)[1]
            log_msg = log_msg.format(realm=realm, site=site)
            self.logger.debug(log_msg)
            raise Exception(log_msg)
        offline = server_session['offline']
        session_key = server_session['session_key']

        if use_dns is None:
            use_dns = config.use_dns

        # Helper method to get JWT from within OTPmeClient().
        def _get_jwt(challenge, use_dns=use_dns):
            return self.get_jwt(login_pid, challenge, use_dns=use_dns)

        # Get login handler.
        login_handler = LoginHandler()
        # Send auth/login request.
        try:
            login_handler.login(username=login_user,
                                realm=realm,
                                site=site,
                                login_use_dns=False,
                                use_dns=use_dns,
                                jwt_auth=True,
                                jwt_method=_get_jwt,
                                auth_only=False,
                                use_ssh_agent=False,
                                use_smartcard=False,
                                endpoint=False,
                                change_user=True,
                                sync_token_data=False,
                                add_agent_session=False,
                                add_login_session=False,
                                need_ssh_key_pass=False,
                                check_login_status=False,
                                cache_login_tokens=False)
        except ConnectionError as e:
            log_msg = _("Login failed: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            self.logger.warning(log_msg)
            raise OTPmeException(log_msg)
        except Exception as e:
            log_msg = _("Login error: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            self.logger.critical(log_msg)
            return False
        # Get RSP.
        rsp = login_handler.login_reply['rsp']
        # Get auth reply.
        auth_reply = login_handler.login_reply['auth_reply']

        # Get session data.
        login_time = auth_reply['login_time']
        timeout = auth_reply['timeout']
        unused_timeout = auth_reply['unused_timeout']
        _slp = auth_reply['slp']

        # Build session dict.
        session = {}
        # Add offline flag..
        session['offline'] = offline
        # Add RSP.
        session['rsp'] = rsp
        # Gen RSP hash.
        rsp_hash = otpme_pass.gen_one_iter_hash(login_user, rsp)
        # Gen SRP.
        _srp = srp.gen(rsp_hash)
        session['srp'] = _srp
        # Add SLP.
        session['slp'] = _slp
        # Add login time.
        session['login_time'] = login_time
        # Set reneg stuff.
        session['next_reneg'] = None
        session['next_retry'] = None
        session['last_reneg'] = time.time()
        session['last_failed_reneg'] = None
        # Set server session timeout stuff.
        session['session_timeout'] = timeout
        session['session_unused_timeout'] = unused_timeout
        # Update login session.
        if not realm in login_session:
            login_session[realm] = {}
        if not site in login_session[realm]:
            login_session[realm][site] = {}
        login_session['server_sessions'][realm][site] = session
        self.login_sessions[login_pid] = login_session
        # Inform main agent loop about a new RSP.
        add_command = f"add_rsp {login_pid}"
        comm_handler = self.comm_queue.get_handler("login_user")
        comm_handler.send(recipient="main_process",
                            command=add_command,
                            timeout=1)
        comm_handler.close()

        # If this session is from the current system user
        # we can try to update the login session file.
        if offline and login_user == config.system_user():
            session_id = self.login_sessions[login_pid]['session_id']
            session_uuid = auth_reply['session']
            session_id = self.login_sessions[login_pid]['session_id']
            try:
                try:
                    shares = session['mounted_shares']
                except KeyError:
                    shares = []
                # Get offline token handler.
                offline_token = OfflineToken()
                # Set user.
                offline_token.set_user(login_user)
                # Acquire offline token lock.
                offline_token.lock()
                # Save RSP.
                offline_token.save_rsp(session_id=session_id,
                                    realm=realm,
                                    site=site,
                                    rsp=rsp,
                                    slp=_slp,
                                    shares=shares,
                                    login_time=login_time,
                                    session_key=session_key,
                                    session_uuid=session_uuid,
                                    session_timeout=timeout,
                                    session_unused_timeout=unused_timeout,
                                    offline_session=offline)
            except Exception as e:
                log_msg = _("Error saving RSP: {error}", log=True)[1]
                log_msg = log_msg.format(error=e)
                self.logger.critical(log_msg)
            finally:
                # Release offline token lock.
                offline_token.unlock()

    def get_daemon_conn(self, realm, site, daemon,
        login_pid, keepalive=False, use_dns=None):
        # Check if we have a session for the given realm/site.
        have_session = False
        if realm in self.login_sessions[login_pid]['server_sessions']:
            if site in self.login_sessions[login_pid]['server_sessions'][realm]:
                have_session = True

        if use_dns is None:
            use_dns = config.use_dns

        if not have_session:
            try:
                self.login_user(login_pid, realm, site, use_dns=use_dns)
            except Exception as e:
                config.raise_exception()
                msg = _("Unable to login to: {realm}/{site}: {e}")
                msg = msg.format(realm=realm, site=site, e=e)
                raise OTPmeException(msg)

        # Lock connection.
        self.acquire_connection_lock(login_pid, realm, site)

        # Indicates that daemon connection was broken.
        broken_conn = False
        # Try to get daemon connection.
        try:
            daemon_conn = self.connections[login_pid][realm][site][daemon]['connection']
        except:
            daemon_conn = None

        if self.config_reload:
            return

        if daemon_conn:
            if keepalive:
                log_msg = _("Sending keepalive message to '{daemon}': {realm}/{site}", log=True)[1]
                log_msg = log_msg.format(daemon=daemon, realm=realm, site=site)
                self.logger.debug(log_msg)
            try:
                status, \
                status_code, \
                reply, \
                binary_data = daemon_conn.send("ping")
            except Exception as e:
                reply = None

            if self.config_reload:
                return

            if reply != "pong":
                log_msg = _("Detected broken connection to '{daemon}'. Trying reconnect...", log=True)[1]
                log_msg = log_msg.format(daemon=daemon)
                self.logger.info(log_msg)
                self.close_daemon_conn(realm, site, daemon, login_pid)
                #daemon_conn.close()
                daemon_conn = None
                broken_conn = True

        if self.config_reload:
            return

        if daemon_conn:
            if not keepalive:
                log_msg = _("Using existing daemon connection to '{daemon}'.", log=True)[1]
                log_msg = log_msg.format(daemon=daemon)
                self.logger.debug(log_msg)
        else:
            if broken_conn:
                log_msg = _("Trying reconnect to daemon '{daemon}'.", log=True)[1]
                log_msg = log_msg.format(daemon=daemon)
                self.logger.info(log_msg)
            else:
                log_msg = _("Connecting to daemon '{daemon}'.", log=True)[1]
                log_msg = log_msg.format(daemon=daemon)
                self.logger.info(log_msg)

            if self.config_reload:
                return

            # Try to get login user.
            try:
                login_user = self.login_sessions[login_pid]['login_user']
            except Exception as e:
                msg, log_msg = _("Error getting login user.", log=True)
                self.logger.critical(log_msg)
                raise OTPmeException(msg)
            # Try to get RSP.
            try:
                rsp = self.login_sessions[login_pid]['server_sessions'][realm][site]['rsp']
            except Exception as e:
                msg, log_msg = _("Error getting RSP.", log=True)
                self.logger.critical(log_msg)
                raise OTPmeException(msg)

            # Connect to daemon.
            try:
                daemon_conn = connections.get(daemon=daemon, realm=realm, site=site,
                                            connect_timeout=self.connect_timeout,
                                            timeout=self.timeout, endpoint=False,
                                            use_agent=False, username=login_user,
                                            rsp=rsp, autoconnect=True,
                                            auto_auth=True, allow_untrusted=True,
                                            sync_token_data=False)
            except AuthFailed as e:
                msg, log_msg = _("Authentication failed while connecting to daemon: {daemon}: {e}", log=True)
                msg = msg.format(daemon=daemon, e=e)
                log_msg = log_msg.format(daemon=daemon, e=e)
                self.logger.warning(log_msg)
                raise AuthFailed(msg)
            except Exception as e:
                msg, log_msg = _("Error getting daemon connection: {daemon}: {e}", log=True)
                msg = msg.format(daemon=daemon, e=e)
                log_msg = log_msg.format(daemon=daemon, e=e)
                self.logger.warning(log_msg)
                raise OTPmeException(msg)
            finally:
                # Make sure there is no orphan connection lock.
                self.release_daemon_conn(realm=realm,
                                        site=site,
                                        daemon=daemon,
                                        login_pid=login_pid)
            if self.config_reload:
                return

            # Add daemon connection to connections dict.
            if daemon_conn:
                if broken_conn:
                    log_msg = _("Connection to daemon '{daemon}' re established.", log=True)[1]
                    log_msg = log_msg.format(daemon=daemon)
                    self.logger.info(log_msg)
                else:
                    log_msg = _("Connection to daemon '{daemon}' established.", log=True)[1]
                    log_msg = log_msg.format(daemon=daemon)
                    self.logger.info(log_msg)

                if login_pid not in self.connections:
                    self.connections[login_pid] = {}

                if realm not in self.connections[login_pid]:
                    self.connections[login_pid][realm] = {}

                if site not in self.connections[login_pid][realm]:
                    self.connections[login_pid][realm][site] = {}

                if daemon not in self.connections[login_pid][realm][site]:
                    self.connections[login_pid][realm][site][daemon] = {}

                try:
                    # Update daemon connection in dict.
                    self.connections[login_pid][realm][site][daemon]['connection'] = daemon_conn
                except Exception as e:
                    msg, log_msg = _("Error updating daemon connection: {e}", log=True)
                    msg = msg.format(e=e)
                    log_msg = log_msg.format(e=e)
                    self.logger.warning(log_msg)
                    raise Exception(msg)

        if self.config_reload:
            return

        # Update connection.
        if daemon_conn:
            # Update last keepalive timestamp.
            try:
                self.connections[login_pid][realm][site][daemon]['last_keepalive'] = time.time()
            except Exception as e:
                msg, log_msg = _("Error updating connecton keepalive timestamp: {e}", log=True)
                msg = msg.format(e=e)
                log_msg = log_msg.format(e=e)
                self.logger.warning(log_msg)
                raise Exception(msg)
            # Update last used timestamp.
            if not keepalive:
                try:
                    self.connections[login_pid][realm][site][daemon]['last_used'] = time.time()
                except Exception as e:
                    msg, log_msg = _("Error updating connecton usage timestamp: {e}", log=True)
                    msg = msg.format(e=e)
                    log_msg = log_msg.format(e=e)
                    self.logger.warning(log_msg)
                    raise Exception(msg)

        if self.config_reload:
            return

        return daemon_conn

    def release_daemon_conn(self, realm, site, daemon, login_pid):
        """ Release daemon connection """
        lock_id = self.build_lock_id(login_pid, realm, site)
        try:
            conn_lock = locking.get_lock(CONN_LOCK_TYPE, lock_id)
        except KeyError:
            return
        conn_lock.release_lock()

    def close_daemon_conn(self, realm, site, daemon, login_pid):
        """ Close daemon connection for given login_pid """
        # Try to close connection.
        try:
            daemon_conn = self.connections[login_pid][realm][site][daemon]['connection']
            daemon_conn.close()
        except:
            pass
        # Remove daemon connection from dict.
        try:
            self.connections[login_pid][realm][site].pop(daemon)
        except:
            pass

    def _conn_proxy(self):
        """
        Forward commands received from connection handler to OTPme daemons.
        """
        # Get communication handler.
        comm_handler = self.comm_queue.get_handler("conn_proxy")
        # Run in loop unitl we get 'quit' command.
        while True:
            # Receive proxy request.
            #sender, command, request = comm_handler.recv(timeout=0.01)
            sender, command, request = comm_handler.recv()
            # Get request data.
            login_pid = request['login_pid']
            realm = request['realm']
            site = request['site']
            daemon = request['daemon']
            try:
                use_dns = request['use_dns']
            except:
                use_dns = config.use_dns

            # Handle commands to ourselves from connection handler.
            if daemon == "agent":
                if command == "login_user":
                    # Try to login user.
                    try:
                        message = self.login_user(login_pid,
                                                realm,
                                                site,
                                                use_dns=use_dns)
                        status_code = status_codes.OK
                    except Exception as e:
                        message = _("Failed to login user: {e}")
                        message = message.format(e=e)
                        status_code = status_codes.ERR

                elif command == "add_session":
                    # Start new thread that will notify us if the login PID
                    # has ended.
                    try:
                        start_thread(name=self.full_name,
                                    target=self.wait_for_pid,
                                    target_args=(login_pid,),
                                    daemon=True)
                        message = _("Session added.")
                        status_code = status_codes.OK
                    except Exception as e:
                        message = _("Failed to add new session: {e}")
                        message = message.format(e=e)
                        status_code = status_codes.ERR

                elif command == "del_session":
                    # Try to logout user.
                    try:
                        message = self.logout_user(login_pid)
                        status_code = status_codes.OK
                    except Exception as e:
                        message = _("Failed to logout user: {e}")
                        message = message.format(e=e)
                        status_code = status_codes.ERR
                    # Delete user session.
                    self.delete_session(login_pid)

                elif command == "add_rsp":
                    # Inform main agent loop about a new RSP.
                    try:
                        add_command = f"add_rsp {login_pid}"
                        comm_handler.send(recipient="main_process",
                                            command=add_command,
                                            timeout=1)
                        message = _("RSP added.")
                        status_code = status_codes.OK
                    except Exception as e:
                        message = _("Failed to add RSP: {e}")
                        message = message.format(e=e)
                        status_code = status_codes.ERR

                elif command == "reneg":
                    # Try to renegotiate realm login session.
                    try:
                        reneg_status = self.reneg_session(login_pid, realm, site)
                        reneg_message = None
                    except Exception as e:
                        reneg_status = False
                        reneg_message = str(e)

                    # Calculate new next renegotiation time.
                    self.get_next_reneg(login_pid, realm, site)
                    # Inform main loop about the reneg we've done.
                    comm_handler.send(recipient="main_process",
                                        command="reneg",
                                        timeout=1)
                    if reneg_status:
                        message = _("Session renegotiation successful.")
                        status_code = status_codes.OK
                    else:
                        if reneg_message:
                            message = reneg_message
                        else:
                            message = _("Session renegotiation failed.")
                        status_code = status_codes.ERR
                else:
                    message = _("Unknown agent command.")
                    status_code = status_codes.ERR
                # Send reply.
                reply_data = {
                            'login_pid'     : login_pid,
                            'status_code'   : status_code,
                            'message'       : message,
                            }
                comm_handler.send(recipient=sender,
                                command="agent_reply",
                                data=reply_data,
                                autoclose=True)
            else:
                proxy_request = request['proxy_request']
                # Proxy command to realm/site/daemon.
                start_thread(name=self.full_name,
                            target=self.proxy_command,
                            target_kwargs={'realm':realm,
                                            'site':site,
                                            'sender':sender,
                                            'daemon':daemon,
                                            'login_pid':login_pid,
                                            'use_dns':use_dns,
                                            'proxy_request':proxy_request},
                            daemon=True)
        # Close comm handler on exit.
        comm_handler.close()

    def proxy_command(self, realm, site, sender, daemon,
        login_pid, proxy_request, use_dns=True):
        """ Proxy command to given realm/site/daemon. """
        # Try to get daemon connection.
        daemon_conn = None
        # Get communication handler.
        comm_handler = self.comm_queue.get_handler("proxy_command")
        while not daemon_conn:
            try:
                daemon_conn = self.get_daemon_conn(realm=realm,
                                                site=site,
                                                daemon=daemon,
                                                login_pid=login_pid,
                                                use_dns=use_dns)
            except AuthFailed as e:
                reply = str(e)
                status_code = status_codes.NEED_USER_AUTH
            except OTPmeException as e:
                reply = str(e)
                status_code = status_codes.ERR
            except Exception as e:
                reply = _("Internal error getting daemon connection.")
                status_code = status_codes.ERR
            if not self.config_reload:
                break

        if not daemon_conn:
            # Send daemon connection error message agent connection.
            reply_data = {
                        'login_pid'     : login_pid,
                        'status_code'   : status_code,
                        'message'       : reply,
                        }
            comm_handler.send(recipient=sender,
                            command="daemon_reply",
                            data=reply_data,
                            autoclose=True)
            comm_handler.close()
            return status_code, reply

        log_msg = _("Sending request to daemon: {daemon}: {realm}/{site}", log=True)[1]
        log_msg = log_msg.format(daemon=daemon, realm=realm, site=site)
        self.logger.debug(log_msg)

        # Get proxy request options.
        command = proxy_request['command']
        command_args = proxy_request['command_args']
        encode_request = proxy_request['encode_request']
        encrypt_request = proxy_request['encrypt_request']

        try:
            status, \
            status_code, \
            reply, \
            binary_data = daemon_conn.send(command=command,
                                    command_args=command_args,
                                    encode_request=encode_request,
                                    encrypt_request=encrypt_request)
        except ConnectionRedirect as e:
            redirect_realm = str(e).split("/")[0]
            redirect_site = str(e).split("/")[1]
            log_msg = _("Got redirected to: {realm}/{site}", log=True)[1]
            log_msg = log_msg.format(realm=redirect_realm, site=redirect_site)
            self.logger.debug(log_msg)
            # We need to release the original daemon connection because it
            # may be needed by get_jwt() to request a JWT for cross-site
            # authentication.
            self.release_daemon_conn(realm=realm,
                                    site=site,
                                    daemon=daemon,
                                    login_pid=login_pid)
            return self.proxy_command(realm=redirect_realm,
                                        site=redirect_site,
                                        sender=sender,
                                        daemon=daemon,
                                        login_pid=login_pid,
                                        proxy_request=proxy_request,
                                        use_dns=use_dns)
        except Exception as e:
            self.close_daemon_conn(realm, site, daemon, login_pid)
            reply = _("Daemon connection broken while sending: {daemon}: {error}")
            reply = reply.format(daemon=daemon, error=e)
            status_code = status_codes.ERR
            log_msg = reply
            self.logger.critical(log_msg)
        finally:
            # Release daemon connection.
            self.release_daemon_conn(realm=realm,
                                    site=site,
                                    daemon=daemon,
                                    login_pid=login_pid)
        # Send daemon reply.
        reply_data = {
                    'login_pid'     : login_pid,
                    'status_code'   : status_code,
                    'message'       : reply,
                    }
        comm_handler.send(recipient=sender,
                        command="daemon_reply",
                        data=reply_data,
                        autoclose=True)
        comm_handler.close()
        return status_code, reply

    def pre_fork(self):
        """ Run stuff before forking. """
        pass
        #hostd_socket_path = config.hostd_socket_path.split(":")[1]
        #if not os.path.exists(hostd_socket_path):
        #    msg = _("Hostd socket not found: {hostd_socket_path}")
        #    msg = msg.format(hostd_socket_path=hostd_socket_path)
        #    error_message(msg)
        #    msg = "Please start otpme-controld."
        #    error_message(msg)
        #    sys.exit(1)

    def run(self):
        """ Run the agent loop. """
        register_module("otpme.lib.classes.realm")
        register_module("otpme.lib.protocols.server.agent1")
        register_module("otpme.lib.offline_token")
        register_module("otpme.lib.sotp")
        from otpme.lib import connections
        # Set PID.
        self.pid = os.getpid()
        # Init otpme.
        init_otpme(use_backend=False)
        # Close connections (e.g. to hostd).
        connections.close_connections()
        # Handle multiprocessing stuff.
        multiprocessing.atfork()
        # Set our name.
        #self.name = "agent"
        # Set daemon mode.
        config.daemon_mode = True
        config.daemon_name = self.name
        # Set tool name in case we where not called from otpme-agent executable.
        config.tool_name = "otpme-agent"
        # Reload config.
        config.reload()

        # Set signal handler.
        signal.signal(signal.SIGTERM, self.signal_handler)
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGHUP, self.signal_handler)

        #import getpass
        #raise Exception(getpass.getuser())

        # Will PIDs (login_pid) of all login processes.
        self.was_used_by = []
        # Set full name.
        self.full_name = f"{config.my_name.lower()}-{self.name}"
        # Create empty list to hold all sockets for this daemon.
        self.sockets = []
        # Agent protocols we support.
        self.protocols = config.get_otpme_protocols(self.name, server=True)
        # Get logger.
        self.logger = config.logger
        # Configure ourselves.
        self.configure()
        # Create manager instance for shared objects.
        multiprocessing.manager = get_sync_manager("otpme-agent", user=self.user)
        # Create shared object dict to hold login session ID to PID mapping.
        self.session_ids = multiprocessing.get_dict()
        # Create shared object dict to hold login session data.
        self.login_sessions = multiprocessing.get_dict()
        # Create list to hold all PID we a currently watching.
        self.watch_pids = multiprocessing.get_list()

        # Handle agent shutdown
        shutdown_name = f"{self.name}:shutdown"
        try:
            self._shutdown = multiprocessing.get_bool(shutdown_name)
        except Exception as e:
            log_msg = _("Failed to get shared bool: {error}", log=True)[1]
            log_msg = log_msg.format(error=e)
            self.logger.critical(log_msg)
            raise

        # Interprocess communication queue. This queue is used to communicate
        # with threads and connected clients.
        self.comm_queue = multiprocessing.InterProcessQueue()
        # Get comm handler for new connections.
        conn_comm_handler = self.comm_queue.get_handler("agent-connections")

        # Pass on shared dicts to agent handler.
        handler_args = {}
        handler_args['session_ids'] = self.session_ids
        handler_args['login_sessions'] = self.login_sessions
        handler_args['comm_handler'] = conn_comm_handler

        # Start connection proxy in new thread.
        start_thread(name=self.full_name, target=self._conn_proxy, daemon=True)

        # Create handler for the new socket.
        conn_handler = ConnHandler(protocols=self.protocols,
                                logger=self.logger,
                                **handler_args)

        # Set agent socket URI.
        self.socket_uri = config.get_agent_socket()
        # Set agent socket banner.
        self.socket_banner = f"{status_codes.OK} {self.full_name} {config.my_version}"
        # Add agent socket.
        self.add_socket(self.socket_uri,
                        handler=conn_handler,
                        banner=self.socket_banner)

        # Start listening on sockets.
        for s in self.sockets:
            try:
                s.listen()
            except Exception as e:
                log_msg = _("Error listening on socket: {error}", log=True)[1]
                log_msg = log_msg.format(error=e)
                self.logger.critical(log_msg)

        log_msg = _("{name}: Connect timeout: {timeout}", log=True)[1]
        log_msg = log_msg.format(name=self.full_name, timeout=self.connect_timeout)
        self.logger.debug(log_msg)

        log_msg = _("{name}: Connection timeout: {timeout}", log=True)[1]
        log_msg = log_msg.format(name=self.full_name, timeout=self.timeout)
        self.logger.debug(log_msg)

        log_msg = _("{name} started", log=True)[1]
        log_msg = log_msg.format(name=self.full_name)
        self.logger.info(log_msg)

        idle_timer = 0
        idle_start = None
        next_interval = 60

        comm_handler = self.comm_queue.get_handler("main_process")
        # Run in loop unitl we get a signal.
        while True:
            # Wait for new daemon command or next interval.
            try:
                sender, \
                daemon_command, \
                data = comm_handler.recv(timeout=next_interval)
            except Exception as e:
                daemon_command = None

            # By default we sleep for one minute.
            next_interval = 60

            if daemon_command == "reload":
                self.config_reload = True
            if daemon_command == "reneg":
                pass
            if daemon_command == "add_rsp":
                pass
            if daemon_command == "pid_ended":
                pass

            if self.config_reload:
                log_msg = _("Starting config reload...", log=True)[1]
                self.logger.info(log_msg)
                # Set our status to config loading to prevent another SIGTERM
                # to initiate another reload which may confuse us.
                self.loading = True
                # We need to close all connections on reload (e.g. to reflect
                # changes of master nodes)
                log_msg = _("Closing all connections on config reload...", log=True)[1]
                self.logger.info(log_msg)
                sessions = dict(self.login_sessions)
                for login_pid in sessions:
                    self.close_user_conns(login_pid)
                # Reload config.
                config.reload()
                # Re-init.
                init_otpme(use_backend=False)
                # Reload config etc.
                self.configure()

            try:
                self.rotate_logfile()
            except Exception as e:
                log_msg = _("Logfile rotation failed: {error}", log=True)[1]
                log_msg = log_msg.format(error=e)
                self.logger.warning(log_msg)

            # Create copy of dicts because they may be changed by _conn_proxy()
            # thread while we are running.
            sessions = dict(self.login_sessions)
            connections = dict(self.connections)
            for login_pid in sessions:
                if self.config_reload:
                    break
                # Add login_pid to list of login processes.
                if not login_pid in self.was_used_by:
                    self.was_used_by.append(login_pid)

                session_type = sessions[login_pid]['session_type']

                # Handle SSH agent sessions (e.g. remove them if the
                # corresponding agent PID is not running anymore).
                if session_type == "ssh_key_pass":
                    # Remove SSH agent session if needed.
                    if not stuff.check_pid(login_pid):
                        log_msg = _("Agent process '{pid}' ended. Removing session.", log=True)[1]
                        log_msg = log_msg.format(pid=login_pid)
                        self.logger.info(log_msg)
                        self.delete_session(login_pid)
                    continue

                if session_type != "realm_login":
                    continue

                # Remove realm login sessions if the corresponding PID is
                # not running anymore.
                if not stuff.check_pid(login_pid):
                    self.close_user_sessions(login_pid)
                    continue
                # Get all server sessions of login_pid.
                try:
                    server_sessions = sessions[login_pid]['server_sessions']
                except:
                    server_sessions = {}

                # Handle realm login sessions (e.g. do reneg or send keepalive).
                for realm in dict(server_sessions):
                    for site in dict(server_sessions[realm]):
                        # Check if we need to renegotiate this session.
                        next_reneg = self.get_next_reneg(login_pid, realm, site)
                        if next_reneg and next_reneg <= time.time():
                            # Try to renegotiate realm login session.
                            try:
                                self.reneg_session(login_pid, realm, site)
                            except:
                                pass
                            # Get new next renegotiation time.
                            next_reneg = self.get_next_reneg(login_pid, realm, site)

                        # Check if we got a valid timestamp for the next
                        # renegotiation.
                        if next_reneg:
                            reneg_interval = next_reneg - time.time()
                            # If current main loop interval is greater than the
                            # renegotiation interval for this session replace it.
                            if next_interval > reneg_interval:
                                next_interval = reneg_interval

                        # Get all connections for login PID we have to send
                        # keepalive packets to.
                        try:
                            login_pid_conns = self.connections[login_pid][realm][site]
                        except:
                            login_pid_conns = {}

                        # Send keepalive messages for valid connections
                        # and close timed out connections.
                        for daemon in dict(login_pid_conns):
                            if self.config_reload:
                                break
                            try:
                                last_used = connections[login_pid][realm][site][daemon]['last_used']
                            except KeyError as e:
                                continue
                            except Exception as e:
                                log_msg = _("Error reading connection last used timestamp: {error}", log=True)[1]
                                log_msg = log_msg.format(error=e)
                                self.logger.critical(log_msg)
                                continue
                            try:
                                last_keepalive = connections[login_pid][realm][site][daemon]['last_keepalive']
                            except KeyError as e:
                                continue
                            except Exception as e:
                                log_msg = _("Error reading connection last keepalive timestamp: {error}", log=True)[1]
                                log_msg = log_msg.format(error=e)
                                self.logger.critical(log_msg)
                                continue

                            conn_age = time.time() - last_used
                            keepalive_age = time.time() - last_keepalive

                            if conn_age > config.agent_connection_idle_timeout:
                                log_msg = _("Closing unused connection to '{daemon}'.", log=True)[1]
                                log_msg = log_msg.format(daemon=daemon)
                                self.logger.info(log_msg)
                                self.close_daemon_conn(realm, site, daemon, login_pid)
                            elif keepalive_age > config.agent_keepalive_interval:
                                # Make sure connection is up.
                                try:
                                    self.get_daemon_conn(realm=realm,
                                                        site=site,
                                                        daemon=daemon,
                                                        login_pid=login_pid,
                                                        keepalive=True)
                                except AuthFailed as e:
                                    log_msg = _("Authentication failed while sending keepalive message to '{daemon}'. Closing connection...", log=True)[1]
                                    log_msg = log_msg.format(daemon=daemon)
                                    self.logger.warning(log_msg)
                                    self.close_daemon_conn(realm, site, daemon, login_pid)
                                except OTPmeException as e:
                                    self.close_daemon_conn(realm, site, daemon, login_pid)
                                    log_msg = _("Unable to send keepalive packet to '{realm}/{site}/{daemon}: {error}", log=True)[1]
                                    log_msg = log_msg.format(realm=realm, site=site, daemon=daemon, error=e)
                                    self.logger.error(log_msg)
                                # Release daemon connection.
                                self.release_daemon_conn(realm=realm,
                                                        site=site,
                                                        daemon=daemon,
                                                        login_pid=login_pid)

            # Check if we are idle. We are idle if there are no login sessions.
            # There may be empty sessions as long as the login PID exists. Which
            # means we will only start the idle counter if any PID that used this
            # agent has ended.
            if len(self.login_sessions) == 0:
                # Agent idle shutdown should only happen if we where used before.
                if len(self.was_used_by) > 0:
                    idle_status = True
                    idle_start = None
                    idle_timer = 0
                    # Check if any of our login PIDs is still running.
                    for login_pid in list(self.was_used_by):
                        if stuff.check_pid(login_pid):
                            idle_status = False
                        else:
                            try:
                                self.was_used_by.remove(login_pid)
                            except:
                                pass
                    if idle_status:
                        idle_start = time.time()

                if idle_start:
                    # Get seconds since idle start.
                    idle_timer = time.time() - idle_start
                    # Check if we reached the idle timeout.
                    if idle_timer >= self.idle_timeout:
                        # If we are still idle (no sessions) go down.
                        if len(self.login_sessions) == 0:
                            log_msg = _("No more login sessions. Terminating on IDLE timeout...", log=True)[1]
                            self.logger.info(log_msg)
                            os._exit(0)
            else:
                idle_start = None
                idle_timer = 0

            # Make sure we sleep not longer than needed.
            if idle_start:
                idle_interval = self.idle_timeout - idle_timer
                if next_interval > idle_timer:
                    next_interval = idle_interval
            if next_interval > config.agent_keepalive_interval:
                next_interval = config.agent_keepalive_interval

            if self.loading:
                # Reset variables.
                self.loading = False
                self.config_reload = False
                log_msg = _("Finished config reload...", log=True)[1]
                self.logger.info(log_msg)

            # FIXME: Changing the sleep time also affects the idle timer!
            time.sleep(1)

    def add_socket(self, socket_uri, handler, banner=None):
        """ Add new socket. """
        # Create new listen socket instance.
        new_socket  = ListenSocket(name=self.full_name,
                                    socket_uri=socket_uri,
                                    connection_handler=handler,
                                    socket_handler=SocketProtoHandler,
                                    banner=banner,
                                    proctitle=config.tool_name,
                                    logger=self.logger,
                                    user=self.user)
        # Append new socket to list of daemon sockets.
        self.sockets.append(new_socket)
        # Return new socket.
        return new_socket

    def close_all_sockets(self):
        """ Close all sockets of this agent """
        log_msg = _("Closing all sockets...", log=True)[1]
        self.logger.debug(log_msg)
        for sock in self.sockets:
            sock.close()

    def rotate_logfile(self):
        """ Rotate agent logfile """
        import gzip
        import glob
        import shutil
        import datetime
        if not self.logfile:
            return
        # Remove old logfile archives.
        rotation_regex = "-[0-9][0-9][0-9][0-9][0-9][0-9][0-9].[0-9].gz"
        logfile_glob = self.logfile + rotation_regex
        old_logs = {(os.path.getmtime(x), x) for x in glob.glob(logfile_glob)}
        if len(old_logs) > self.logfile_max_rotate:
            obsolete_logs = sorted(old_logs, reverse=True)
            obsolete_logs = obsolete_logs[self.logfile_max_rotate-1:]
            #obsolete_logs = list(sorted(old_logs, reverse=True))[self.logfile_max_rotate-1:]
            for x in obsolete_logs:
                old_logfile = x[1]
                log_msg = _("Removing outdated logfile: {logfile}", log=True)[1]
                log_msg = log_msg.format(logfile=old_logfile)
                self.logger.debug(log_msg)
                try:
                    os.remove(old_logfile)
                except Exception as e:
                    log_msg = _("Error removing outdate logfile: {error}", log=True)[1]
                    log_msg = log_msg.format(error=e)
                    self.logger.warning(log_msg)

        # Check if we have to rotate the current logfile.
        logfile_size = int(os.path.getsize(self.logfile) / 1024)
        if logfile_size < self.logfile_rotate_size:
            return

        log_msg = _("Starting logfile rotation...", log=True)[1]
        self.logger.debug(log_msg)
        tmp_logfile = f"{self.logfile}.tmp"
        count = 0
        now = datetime.datetime.now()
        while True:
            zip_logfile = f"{self.logfile}-{now.year}{now.month}{now.day}.{count}.gz"
            if not os.path.exists(zip_logfile):
                break
            count += 1
        # Rename current logfile.
        try:
            os.rename(self.logfile, tmp_logfile)
        except Exception as e:
            msg = _("Error renaming current logfile: {e}")
            msg = msg.format(e=e)
            raise OTPmeException(msg)
        # Start logging to new empty logfile.
        self.configure_logger()
        # Open old logfile for reading.
        try:
            input_file = open(tmp_logfile, 'rb')
        except Exception as e:
            msg = _("Error opening current logfile: {e}")
            msg = msg.format(e=e)
            raise OTPmeException(msg)
        # Open gzip destination file for writing.
        try:
            output_file = gzip.open(zip_logfile, 'wb')
        except Exception as e:
            msg = _("Error opening rotation logfile: {e}")
            msg = msg.format(e=e)
            raise OTPmeException(msg)
        # Compress old logfile.
        try:
            shutil.copyfileobj(input_file, output_file)
        except Exception as e:
            msg = _("Error while compressing logfile: {e}")
            msg = msg.format(e=e)
            raise OTPmeException(msg)
        # Remove old logfile.
        try:
            os.remove(tmp_logfile)
        except Exception as e:
            msg = _("Error removing temporary logfile: {e}")
            msg = msg.format(e=e)
            raise OTPmeException(msg)

        log_msg = _("Logfile rotation finished successful.", log=True)[1]
        self.logger.debug(log_msg)
