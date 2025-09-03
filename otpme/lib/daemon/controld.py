# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import sys
import time
import signal
import setproctitle

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import net
from otpme.lib import host
from otpme.lib import stuff
from otpme.lib import cache
from otpme.lib import config
from otpme.lib import init_otpme
from otpme.lib import multiprocessing
#from otpme.lib.stuff import add_decorators
from otpme.lib.messages import error_message
from otpme.lib.register import register_modules

from otpme.lib.daemon.fsd import FsDaemon
from otpme.lib.daemon.authd import AuthDaemon
from otpme.lib.daemon.mgmtd import MgmtDaemon
from otpme.lib.daemon.syncd import SyncDaemon
from otpme.lib.daemon.hostd import HostDaemon
from otpme.lib.daemon.joind import JoinDaemon
from otpme.lib.daemon.httpd import HttpDaemon
from otpme.lib.daemon.scriptd import ScriptDaemon
from otpme.lib.daemon.clusterd import ClusterDaemon
from otpme.lib.daemon.unix_daemon import UnixDaemon
#from otpme.lib.multiprocessing import handle_exit

from otpme.lib.exceptions import *

from otpme.lib.daemon.ldapd import LdapDaemon

REGISTER_BEFORE = []
REGISTER_AFTER = []

def register():
    """ Register daemon stuff. """
    # Register daemon status stuff.
    def get_daemon_status_file(self, daemon_name):
        status_file_name = "otpme-%s.status" % daemon_name
        status_file = os.path.join(self.pidfile_dir, status_file_name)
        return status_file
    def read_daemon_status(self, daemon_name):
        """ Get daemon status from status file. """
        import json
        from otpme.lib import filetools
        status_file = self.get_daemon_status_file(daemon_name)
        try:
            status_data = filetools.read_file(status_file)
        except Exception as e:
            msg = "Failed to load daemon status: %s" % e
            raise OTPmeException(msg)
        try:
            status_data = json.loads(status_data)
        except Exception as e:
            msg = "Failed to decode daemon status: %s" % e
            raise OTPmeException(msg)
        return status_data
    def write_daemon_status(self, daemon_name, status_data):
        """ Write daemon status to status file. """
        import json
        from otpme.lib import filetools
        status_file = self.get_daemon_status_file(daemon_name)
        try:
            status_data = json.dumps(status_data, sort_keys=True, indent=4)
        except Exception as e:
            msg = "Failed to encode daemon status: %s" % e
            raise OTPmeException(msg)
        try:
            filetools.create_file(status_file, status_data)
        except Exception as e:
            msg = "Failed to write daemon status: %s" % e
            raise OTPmeException(msg)
    def daemon_status_getter(self):
        """ Daemon status. """
        if self.daemon_name is None:
            msg = "config.daemon_name not set."
            raise OTPmeException(msg)
        status_data = self.read_daemon_status(self.daemon_name)
        try:
            _status = status_data['status']
        except:
            _status = None
        return _status
    def daemon_status_setter(self, new_status):
        if self.daemon_name is None:
            msg = "config.daemon_name not set."
            raise OTPmeException(msg)
        status_data = {}
        status_data['pid'] = os.getpid()
        status_data['status'] = new_status
        self.write_daemon_status(self.daemon_name, status_data)
    config.register_method("get_daemon_status_file", get_daemon_status_file)
    config.register_method("read_daemon_status", read_daemon_status)
    config.register_method("write_daemon_status", write_daemon_status)
    config.register_property(name="daemon_status",
                            getx=daemon_status_getter,
                            setx=daemon_status_setter)
    def pid_getter(self):
        """ Get daemon PID from status file. """
        if config.daemon_name is None:
            msg = "config.daemon_name not set."
            raise OTPmeException(msg)
        status_data = self.read_daemon_status(config.daemon_name)
        try:
            _pid = status_data['pid']
        except:
            _pid = None
        return _pid
    config.register_property(name="daemon_pid", getx=pid_getter)
    # Register daemon shutdown status property.
    def daemon_shutdown_getter(self):
        try:
            return config._daemon_shutdown.value
        except AttributeError:
            return False
    def daemon_shutdown_setter(self, new_status):
        config._daemon_shutdown.value = new_status
    config.register_property(name="daemon_shutdown",
                            getx=daemon_shutdown_getter,
                            setx=daemon_shutdown_setter)
    config.register_config_var("_daemon_shutdown", None, False)
    # Register cluster quorum property.
    def cluster_quorum_getter(self):
        try:
            return config._cluster_quorum.value
        except AttributeError:
            return False
    def cluster_quorum_setter(self, new_status):
        config._cluster_quorum.value = new_status
    config.register_property(name="cluster_quorum",
                            getx=cluster_quorum_getter,
                            setx=cluster_quorum_setter)
    config.register_config_var("_cluster_quorum", None, False)
    # Register cluster status property.
    def cluster_status_getter(self):
        try:
            return config._cluster_status.value
        except AttributeError:
            return False
    def cluster_status_setter(self, new_status):
        config._cluster_status.value = new_status
    config.register_property(name="cluster_status",
                            getx=cluster_status_getter,
                            setx=cluster_status_setter)
    config.register_config_var("_cluster_status", None, False)
    # Register cluster vote participation property.
    def cluster_vote_participation_getter(self):
        try:
            return config._cluster_vote_participation.value
        except AttributeError:
            return False
    def cluster_vote_participation_setter(self, new_status):
        config._cluster_vote_participation.value = new_status
    config.register_property(name="cluster_vote_participation",
                            getx=cluster_vote_participation_getter,
                            setx=cluster_vote_participation_setter)
    config.register_config_var("_cluster_vote_participation", None, False)
    # Register master failover property.
    def master_failover_getter(self):
        try:
            return config._master_failover.value
        except AttributeError:
            return False
    def master_failover_setter(self, new_status):
        config._master_failover.value = new_status
    config.register_property(name="master_failover",
                            getx=master_failover_getter,
                            setx=master_failover_setter)
    config.register_config_var("_master_failover", None, False)
    # Register one node setup property.
    def one_node_setup_getter(self):
        try:
            return config._one_node_setup.value
        except AttributeError:
            return False
    def one_node_setup_setter(self, new_status):
        config._one_node_setup.value = new_status
    config.register_property(name="one_node_setup",
                            getx=one_node_setup_getter,
                            setx=one_node_setup_setter)
    config.register_config_var("_one_node_setup", None, False)
    # Register two node setup property.
    def two_node_setup_getter(self):
        try:
            return config._two_node_setup.value
        except AttributeError:
            return False
    def two_node_setup_setter(self, new_status):
        config._two_node_setup.value = new_status
    config.register_property(name="two_node_setup",
                            getx=two_node_setup_getter,
                            setx=two_node_setup_setter)
    config.register_config_var("_two_node_setup", None, False)
    # Register site init property.
    def site_init_getter(self):
        if config.daemon_mode:
            try:
                return config._site_init.value
            except AttributeError:
                return False
        else:
            return config._site_init
    def site_init_setter(self, new_status):
        if config.daemon_mode:
            try:
                config._site_init.value = new_status
            except AttributeError:
                return
        else:
            config._site_init = new_status
    config.register_property(name="site_init",
                            getx=site_init_getter,
                            setx=site_init_setter)
    config.register_config_var("_site_init", None, False)
    # Register ldap cache clear property.
    def ldap_cache_clear_getter(self):
        try:
            return config._ldap_cache_clear.value
        except AttributeError:
            return False
    def ldap_cache_clear_setter(self, new_status):
        config._ldap_cache_clear.value = new_status
    config.register_property(name="ldap_cache_clear",
                            getx=ldap_cache_clear_getter,
                            setx=ldap_cache_clear_setter)
    config.register_config_var("_ldap_cache_clear", None, False)
    # Register ldap object changed property.
    def ldap_object_changed_getter(self):
        if isinstance(config._ldap_object_changed, bool):
            return config._ldap_object_changed
        try:
            return config._ldap_object_changed.value
        except AttributeError:
            return False
    def ldap_object_changed_setter(self, new_status):
        if isinstance(config._ldap_object_changed, bool):
            config._ldap_object_changed = new_status
            return
        config._ldap_object_changed.value = new_status
    config.register_property(name="ldap_object_changed",
                            getx=ldap_object_changed_getter,
                            setx=ldap_object_changed_setter)
    config.register_config_var("_ldap_object_changed", None, False)
    # Register sync status stuff.
    def sync_status_getter(self):
        from otpme.lib.multiprocessing import sync_status
        return sync_status
    config.register_property(name="sync_status", getx=sync_status_getter)
    multiprocessing.register_shared_dict("sync_status", clear=True)

class ControlDaemon(UnixDaemon):
    """
    ControlDaemon that will start/stop other daemons with lower privilege level.
    """
    def __init__(self, *args, **kwargs):
        # Set daemon name.
        self.name = "controld"
        self.comm_id = "controld-master"
        self.child_comm_id = "controld"
        # Set full name.
        self.full_name = "%s-%s" % (config.my_name.lower(), self.name)
        # Inter-daemon communication timeout.
        self.daemon_msg_timeout = config.inter_daemon_comm_timeout
        # Indicates that there is an ongoing config reload.
        self.loading = False
        self.need_restart = False
        # Will hold site address if we are site master.
        self.floating_address = None
        # Will hold daemon names we have to handle and their start order.
        self.daemons = []
        # List that will hold all childs daemons.
        self.childs = {}
        # Set own PID.
        self.pid = None
        # Our status file.
        self.status_file = config.get_daemon_status_file(self.name)
        # Do not send heartbeat messages to this daemons.
        self.no_heartbeat_daemons = []
        # Daemon handler process.
        self.daemon_handler_proc = None
        # Call parent class init.
        super(ControlDaemon, self).__init__(self.full_name, *args, **kwargs)

    def signal_handler(self, _signal, frame):
        """ Handle signals and notify ourselves via queue.put() """
        if self.daemon_startup.value:
            return
        signal_name = stuff.get_signal_name(_signal)
        if signal_name == "SIGINT":
            self.logger.warning("Exiting on Ctrl+C")
            stuff.kill_pid(self.pid)
        if signal_name == "SIGTERM":
            self.logger.warning("Exiting on 'SIGTERM'.")
        if signal_name == "SIGHUP":
            self.logger.warning("Received 'SIGHUP'.")

        if signal_name == "SIGHUP":
            if not self.loading:
                # Notify ourselves about the reload singal.
                self.comm_handler.send(recipient="controld", command="reload")
            return

        config.daemon_shutdown = True
        config.master_failover = True

        # Do shutdown stuff only in daemon handler process.
        if not config.daemonize:
            if self.pid == os.getpid():
                while not self._cleanup_done.value:
                    time.sleep(0.01)
                os._exit(0)

        # Stop daemon handler process.
        if self.daemon_handler_proc:
            self.daemon_handler_proc.terminate()
            self.daemon_handler_proc.join()

        # Stop all child daemons.
        self.stop_all_childs()
        # Close and remove message queues.
        self.comm_queue.close()
        self.comm_queue.unlink()
        self.comm_handler.close()
        self.comm_handler.unlink()

        keep_floating_ip = False
        if config.site_address == "127.0.0.1":
            keep_floating_ip = True
        if config.keep_floating_ip:
            keep_floating_ip = True

        # Deconfigure floating IP. This must be done at this stage to prevent an
        # orphan floating IP.
        if not keep_floating_ip:
            self.deconfigure_floating_ip()

        ## Close log handlers.
        #for h in self.logger.handlers:
        #    h.close()

        # Stop cache.
        self._stop_cache()
        # Stop index (e.g. postgresql).
        self._stop_index()

        msg = "Control daemon shutdown succeeded."
        self.logger.info(msg)
        self._cleanup_done.value = True
        if os.path.exists(self.status_file):
            os.remove(self.status_file)
        # Remove pidfile.
        self.remove_pidfile()
        # Close shared objects.
        try:
            self._cleanup_done.close()
        except Exception as e:
            msg = ("Failed to close shared bool: %s" % self._cleanup_done.name)
            self.logger.critical(msg)
        try:
            self.daemon_startup.close()
        except Exception as e:
            msg = ("Failed to close shared bool: %s"
                % config.daemon_startup.name)
            self.logger.critical(msg)
        try:
            config._daemon_shutdown.close()
        except Exception as e:
            msg = ("Failed to close shared bool: %s"
                % config._daemon_shutdown.name)
            self.logger.critical(msg)
        try:
            config._cluster_quorum.close()
        except Exception as e:
            msg = ("Failed to close shared bool: %s"
                % config._cluster_quorum.name)
            self.logger.critical(msg)
        try:
            config._cluster_status.close()
        except Exception as e:
            msg = ("Failed to close shared bool: %s"
                % config._cluster_status.name)
            self.logger.critical(msg)
        try:
            config._cluster_vote_participation.close()
        except Exception as e:
            msg = ("Failed to close shared bool: %s"
                % config._cluster_vote_participation.name)
            self.logger.critical(msg)
        try:
            config._master_failover.close()
        except Exception as e:
            msg = ("Failed to close shared bool: %s"
                % config._master_failover.name)
            self.logger.critical(msg)
        try:
            config._one_node_setup.close()
        except Exception as e:
            msg = ("Failed to close shared bool: %s"
                % config._one_node_setup.name)
            self.logger.critical(msg)
        try:
            config._two_node_setup.close()
        except Exception as e:
            msg = ("Failed to close shared bool: %s"
                % config._two_node_setup.name)
            self.logger.critical(msg)
        try:
            config._site_init.close()
        except Exception as e:
            msg = ("Failed to close shared bool: %s"
                % config._site_init.name)
            self.logger.critical(msg)
        try:
            config._ldap_cache_clear.close()
        except Exception as e:
            msg = ("Failed to close shared bool: %s"
                % config._ldap_cache_clear.name)
            self.logger.critical(msg)
        try:
            config._ldap_object_changed.close()
        except Exception as e:
            msg = ("Failed to close shared bool: %s"
                % config._ldap_object_changed.name)
            self.logger.critical(msg)
        #try:
        #    multiprocessing.cluster_lock_event.unlink()
        #except Exception as e:
        #    msg = "Failed to remove cluster event: %s" % e
        #    self.logger.critical(msg)
        try:
            multiprocessing.cluster_in_event.unlink()
        except Exception as e:
            msg = "Failed to remove cluster event: %s" % e
            self.logger.critical(msg)
        try:
            multiprocessing.cluster_out_event.unlink()
        except Exception as e:
            msg = "Failed to remove cluster event: %s" % e
            self.logger.critical(msg)
        try:
            multiprocessing.two_node_setup_event.unlink()
        except Exception as e:
            msg = "Failed to remove cluster event: %s" % e
            self.logger.critical(msg)
        os._exit(0)

    @property
    def comm_handler(self):
        """ Get comm handler for this process. """
        comm_handler = self.comm_queue.get_handler(self.comm_id)
        return comm_handler

    def configure_floating_ip(self, address):
        """ Configure floating IP. """
        if address != self.floating_address:
            self.deconfigure_floating_ip()
        try:
            net.configure_floating_ip(address)
        except AddressAlreadyAssigned as e:
            self.logger.warning(str(e))
        except AddressAlreadyInUse as e:
            self.logger.warning(str(e))
        except Exception as e:
            msg = (_("Unable to configure floating IP for site: %s: %s")
                    % (config.site, e))
            self.logger.critical(msg)
            raise Exception(msg)
        # Remember address we configured.
        self.floating_address = address

    def deconfigure_floating_ip(self, address=None):
        """ Deconfigure floating IP. """
        if address is None and self.floating_address is not None:
            address = self.floating_address
        if not address:
            return
        try:
            net.deconfigure_floating_ip(address)
        except Exception as e:
            msg = (_("Unable to deconfigure floating IP for site: %s: %s")
                    % (config.site ,e))
            self.logger.critical(msg)
            raise Exception(msg)

    def configure(self):
        """ Make sure we are configured correctly. """
        if not "name" in config.host_data or not config.host_data['name']:
            msg = (_("Don't know my hostname. Please make sure %s points to the "
                    "correct OTPme object UUID.") % config.uuid_file)
            raise OTPmeException(msg)

        if not config.host_data['type']:
            msg = (_("Uuhh, '%s' does not have host type set. This is most "
                    "likely a result of a broken object configuration.")
                        % config.host_data['name'])
            raise OTPmeException(msg)

        child_daemons = {}
        if config.host_data['type'] == "node":
            # Daemons we have to handle and its start order.
            self.daemons = [
                    'hostd',
                    'mgmtd',
                    'ldapd',
                    'joind',
                    'scriptd',
                    'syncd',
                    'authd',
                    'clusterd',
                    'httpd',
                    'fsd',
                    ]

            # Set child daemons.
            child_daemons["fsd"] = {}
            child_daemons["authd"] = {}
            child_daemons["hostd"] = {}
            child_daemons["joind"] = {}
            child_daemons["ldapd"] = {}
            child_daemons["httpd"] = {}
            child_daemons["mgmtd"] = {}
            child_daemons["syncd"] = {}
            child_daemons["scriptd"] = {}
            child_daemons["clusterd"] = {}

        if config.host_data['type'] == "host":
            # Daemons we have to handle and its start order.
            self.daemons = [ 'hostd' ]
            # Set child daemons.
            child_daemons['hostd'] = ""

        # Stop child daemons not needed anymore.
        all_childs = set(list(self.childs) + list(child_daemons))
        for x in all_childs:
            if x in child_daemons:
                if x not in self.childs:
                    self.childs[x] = {}
                continue
            if x not in self.childs:
                continue
            self.childs.pop(x)
            self.logger.info("Removing child daemon.")

    def run(self):
        """ Start daemon loop. """
        from otpme.lib import filetools
        # Register modules.
        register_modules()
        # Set own PID.
        self.pid = os.getpid()
        # Set daemon mode.
        config.daemon_mode = True
        config.daemon_name = self.name
        # Make sure we use direct backend access.
        config.use_backend = True
        # Create OTPmeFS mount point root dir.
        if config.mount_root_dir:
            directories = {
                            config.mount_root_dir : 0o770,
                        }
            filetools.ensure_fs_permissions(directories=directories,
                                            user="root",
                                            group=config.realm_users_group)
        # Handle multiprocessing stuff.
        multiprocessing.atfork()
        # Enable file logging if run in daemon  mode.
        if config.daemonize:
            config.file_logging = True
        # Setup logger.
        log_banner = "%s:" % self.full_name
        self.logger = config.setup_logger(banner=log_banner,
                                        pid=self.pid,
                                        existing_logger=config.logger)
        if not os.path.exists(config.uuid_file):
            msg = (_("Host is not a realm member."))
            raise OTPmeException(msg)
        ## Blacklists for exit handler decorator.
        #blacklist_methods = [
        #                    '__getattr__',
        #                    '__setattr__',
        #                    'otpme.lib.ldap',
        #                    'otpme.lib.debug',
        #                    'otpme.lib.cache',
        #                    'otpme.lib.socket',
        #                    'otpme.lib.daemon',
        #                    'otpme.lib.locking',
        #                    'otpme.lib.filetools',
        #                    #'otpme.lib.protocols',
        #                    'otpme.lib.multiprocessing',
        #                    ]
        #blacklist_functions = blacklist_methods
        ## Add exit handler decorator to ensure clean process exit (e.g. on signal).
        #add_decorators(decorator=handle_exit,
        #            blacklist_methods=blacklist_methods,
        #            blacklist_functions=blacklist_functions)

        multiprocessing.cluster_in_event = multiprocessing.Event()
        multiprocessing.cluster_out_event = multiprocessing.Event()
        multiprocessing.two_node_setup_event = multiprocessing.Event()
        #multiprocessing.cluster_lock_event = multiprocessing.Event()

        daemon_startup = "otpme-daemon-startup"
        try:
            self.daemon_startup = multiprocessing.get_bool(daemon_startup,
                                                        random_name=False)
        except Exception as e:
            msg = "Failed to get shared bool: %s" % e
            self.logger.critical(msg)
        # Mark daemon startup as True.
        self.daemon_startup.value = True
        daemon_shutdown = "otpme-daemon-shutdown"
        try:
            config._daemon_shutdown = multiprocessing.get_bool(daemon_shutdown,
                                                            random_name=False)
        except Exception as e:
            msg = "Failed to get shared bool: %s" % e
            self.logger.critical(msg)
        cluster_quorum = "otpme-cluster-quorum"
        try:
            config._cluster_quorum = multiprocessing.get_bool(cluster_quorum,
                                                            random_name=False)
        except Exception as e:
            msg = "Failed to get shared bool: %s" % e
            self.logger.critical(msg)
        cluster_status = "otpme-cluster-status"
        try:
            config._cluster_status = multiprocessing.get_bool(cluster_status,
                                                            random_name=False)
        except Exception as e:
            msg = "Failed to get shared bool: %s" % e
            self.logger.critical(msg)
        cluster_vote_participation = "otpme-cluster-vote-participation"
        try:
            config._cluster_vote_participation = multiprocessing.get_bool(cluster_vote_participation,
                                                                        random_name=False)
        except Exception as e:
            msg = "Failed to get shared bool: %s" % e
            self.logger.critical(msg)
        master_failover = "otpme-master-failover"
        try:
            config._master_failover = multiprocessing.get_bool(master_failover,
                                                            random_name=False)
        except Exception as e:
            msg = "Failed to get shared bool: %s" % e
            self.logger.critical(msg)
        one_node_setup = "otpme-one-node-setup"
        try:
            config._one_node_setup = multiprocessing.get_bool(one_node_setup,
                                                            random_name=False)
        except Exception as e:
            msg = "Failed to get shared bool: %s" % e
            self.logger.critical(msg)
        two_node_setup = "otpme-two-node-setup"
        try:
            config._two_node_setup = multiprocessing.get_bool(two_node_setup,
                                                            random_name=False)
        except Exception as e:
            msg = "Failed to get shared bool: %s" % e
            self.logger.critical(msg)
        cleanup_done_name = "%s:cleanup_done" % self.name
        try:
            self._cleanup_done = multiprocessing.get_bool(cleanup_done_name,
                                                        random_name=False)
        except Exception as e:
            msg = "Failed to get shared bool: %s" % e
            self.logger.critical(msg)
        site_init = "otpme-site-init"
        try:
            config._site_init = multiprocessing.get_bool(site_init,
                                                        random_name=False)
        except Exception as e:
            msg = "Failed to get shared bool: %s" % e
            self.logger.critical(msg)
        ldap_cache_clear = "ldap-cache-clear"
        try:
            config._ldap_cache_clear = multiprocessing.get_bool(ldap_cache_clear,
                                                            random_name=False)
        except Exception as e:
            msg = "Failed to get shared bool: %s" % e
            self.logger.critical(msg)

        ldap_object_changed = "ldap-object-changed"
        try:
            config._ldap_object_changed = multiprocessing.get_bool(ldap_object_changed,
                                                            random_name=False)
        except Exception as e:
            msg = "Failed to get shared bool: %s" % e
            self.logger.critical(msg)

        # Start index (e.g. postgresql).
        try:
            self._start_index()
        except Exception as e:
            msg = "Failed to start index: %s" % e
            self.logger.critical(msg)

        # Start cache.
        try:
            self._start_cache()
        except Exception as e:
            msg = "Failed to start cache: %s" % e
            self.logger.critical(msg)

        # Flush cache if configured.
        if config.flush_cache_on_start:
            try:
                self._flush_cache()
            except Exception as e:
                msg = "Failed to flush cache: %s" % e
                self.logger.critical(msg)

        # Init cache.
        try:
            cache.init()
        except Exception as e:
            msg = "Failed to init cache: %s" % e
            self.logger.critical(msg)
        try:
            cache.enable()
        except Exception as e:
            msg = "Failed to enable cache: %s" % e
            self.logger.critical(msg)

        # Init OTPme (e.g. get config.host_data).
        try:
            init_otpme()
        except Exception as e:
            msg = "Failed to init OTPme: %s" % e
            self.logger.critical(msg)
            config.raise_exception()

        # Enable file logging if not in debug mode.
        if not config.debug_enabled:
            try:
                config.reload()
            except Exception as e:
                msg = "Failed to reload config: %s" % e
                self.logger.critical(msg)

        # Configure ourselves.
        try:
            self.configure()
        except DaemonRestart:
            pass
        except Exception as e:
            msg = "Failed to configure controld: %s" % e
            self.logger.critical(msg)
            config.raise_exception()

        # Interprocess communication queue.
        try:
            self.comm_queue = multiprocessing.InterProcessQueue()
        except Exception as e:
            msg = "Failed to init interprocess queue: %s" % e
            self.logger.critical(msg)

        # Set signal handler after we finished initialization.
        signal.signal(signal.SIGTERM, self.signal_handler)
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGHUP, self.signal_handler)

        # Create shared objects.
        try:
            multiprocessing.create_shared_objects()
        except Exception as e:
            msg = "Failed to create shared objects: %s" % e
            self.logger.critical(msg)

        # Set daemon status.
        config.daemon_status = "running"

        msg = "Updating host data..."
        self.logger.info(msg)
        try:
            host.update_data()
        except Exception as e:
            msg = "Failed to update host data: %s" % e
            self.logger.critical(msg)
            config.raise_exception()

        # Load sync status from file.
        try:
            config.load_sync_status()
        except Exception as e:
            msg = "Failed to load sync status: %s" % e
            self.logger.critical(msg)

        self.logger.info("%s started" % self.full_name)

        # Start process to handle daemon commands. This is needed to prevent
        # problems when child daemons are started from a process of controld.
        try:
            self.daemon_handler_proc = multiprocessing.start_process(name=self.name,
                                                                target=self._run)
        except Exception as e:
            msg = "Failed to start daemon handler process: %s" % e
            self.logger.critical(msg)

        # Wait for command process to startup child daemons.
        try:
            self.comm_handler.send(self.child_comm_id, command="start_daemons")
        except Exception as e:
            msg = "Failed to send daemon start command to handler process: %s" % e
            self.logger.critical(msg)
        while True:
            try:
                sender, \
                startup_message, \
                data = self.comm_handler.recv(timeout=0.01)
            except TimeoutReached:
                startup_message = None
            except ExitOnSignal:
                sys.exit(0)
            if startup_message is None:
                continue
            if startup_message == "daemons_ready":
                break
            #if startup_message == "quit":
            #    sys.exit()
            msg = "Failed to get daemon command: %s" % startup_message
            self.logger.critical(msg)
            sys.exit(1)

        last_host_data_reload = 0
        # FIXME: make this an config file option?
        host_data_reload_interval = 30
        # Set shorter interval for first keepalive packet because hostd will
        # start first sync after receiving the first keepalive packet.
        keepalive_interval = 3
        while True:
            # Get next interval we have to wait for.
            time.sleep(keepalive_interval)
            # Interval in seconds we check for child daemons to be healthy.
            keepalive_interval = config.controld_heartbeat_interval
            # Send keepalive command to command process.
            self.comm_handler.send(self.child_comm_id, command="send_keepalive")
            # Try to update our host data.
            host_data_age = time.time() - last_host_data_reload
            if host_data_age < host_data_reload_interval:
                continue
            try:
                host.update_data()
                last_host_data_reload = time.time()
            except Exception as e:
                msg = "Failed to update host data: %s" % e
                self.logger.critical(msg)
                config.raise_exception()

        self.daemon_handler_proc.join()

    def _run(self):
        """ Run loop to handle daemon commands. """
        # Handle multiprocessing stuff.
        multiprocessing.atfork()
        # Set process title for handler process.
        proctitle = "%s (daemon handler)" % self.full_name
        try:
            setproctitle.setproctitle(proctitle)
        except Exception as e:
            msg = "Failed to set proctitle: %s" % e
            self.logger.critical(msg)
        self.comm_id = self.child_comm_id

        while True:
            try:
                sender, command, data = self.comm_handler.recv()
            except TimeoutReached:
                continue
            except ExitOnSignal:
                break
            except EOFError as e:
                msg = "EOFError while receiving command: %s" % e
                self.logger.critical(msg)
                continue
            except IOError as e:
                msg = "IOError while receiving command: %s" % e
                self.logger.critical(msg)
                continue
            except Exception as e:
                msg = "Failed to get daemon command: %s" % e
                self.logger.critical(msg, exc_info=True)
                continue

            if command == "start_daemons":
                # Start child daemons.
                try:
                    start_status = self.ensure_daemons()
                except Exception as e:
                    msg = "Failed to start daemons: %s" % e
                    self.logger.critical(msg)
                    pass
                if start_status is False:
                    # Inform main process about failure.
                    self.comm_handler.send(sender, command="startup_failed")
                    # Leave loop to stop daemons.
                    break
                #if start_status is None:
                #    # Inform main process about daemon shutdown.
                #    self.comm_handler.send(sender, command="quit")
                #    # Leave loop to stop daemons.
                #    break
                # Inform main process about startup.
                self.comm_handler.send(sender, command="daemons_ready")
                self.daemon_startup.value = False
            elif command == "send_keepalive":
                self.ensure_daemons()
            elif command == "configure_floating_ip":
                try:
                    self.configure_floating_ip(config.site_address)
                except Exception as e:
                    msg = "Failed to configure floating IP: %s" % e
                    self.logger.critical(msg)
                    config.raise_exception()
                self.comm_handler.send(sender, command="ip_configured")
            elif command == "deconfigure_floating_ip":
                self.deconfigure_floating_ip()
                self.comm_handler.send(sender, command="ip_deconfigured")
                #self.need_restart = True
            elif command == "reload":
                self._reload()
            else:
                msg = "Unknown daemon command: %s" % command
                raise OTPmeException(msg)

    def _start_index(self):
        """ Start index. """
        _index = config.get_index_module()
        if not _index.need_start:
            return
        if config.autostart_index:
            if _index.status():
                return
            _index.start()
            _index.wait_for_start()
            return
        if _index.status():
            return
        msg = "Index not started."
        error_message(msg)
        self.logger.critical(msg)
        sys.exit(1)

    def _reload_index(self):
        """ Stop index. """
        _index = config.get_index_module()
        if not _index.need_start:
            return
        if not _index.status():
            return
        _index._reload()

    def _stop_index(self):
        """ Stop index. """
        _index = config.get_index_module()
        if not _index.need_start:
            return
        if not config.autostart_index:
            return
        if not _index.status():
            return
        _index.stop()

    def _start_cache(self):
        """ Start cache. """
        _cache = config.get_cache_module()
        if config.autostart_cache:
            if _cache.status():
                return
            _cache.start()
            _cache.wait_for_start()
            return
        if _cache.status():
            return
        msg = "Cache not started."
        error_message(msg)
        self.logger.critical(msg)
        sys.exit(1)

    def _stop_cache(self):
        """ Stop cache. """
        if not config.autostart_cache:
            return
        _cache = config.get_cache_module()
        if not _cache.status():
            return
        _cache.stop()

    def _flush_cache(self):
        """ Flush cache. """
        _cache = config.get_cache_module()
        if not _cache.status():
            msg = "Cache not started."
            raise NotRunning(msg)
        _cache.flushall()

    def start_daemon(self, daemon_name, reload=False, master_node=False):
        """ Start child daemon by name. """
        # Set daemon user/group.
        daemon_user = config.user
        daemon_group = config.group

        if daemon_name == "authd":
            daemon_class = AuthDaemon
        elif daemon_name == "hostd":
            daemon_class = HostDaemon
        elif daemon_name == "joind":
            daemon_class = JoinDaemon
        elif daemon_name == "httpd":
            daemon_class = HttpDaemon
        elif daemon_name == "ldapd":
            daemon_class = LdapDaemon
        elif daemon_name == "mgmtd":
            daemon_class = MgmtDaemon
        elif daemon_name == "syncd":
            daemon_class = SyncDaemon
        elif daemon_name == "scriptd":
            daemon_class = ScriptDaemon
        elif daemon_name == "fsd":
            daemon_class = FsDaemon
        elif daemon_name == "clusterd":
            daemon_class = ClusterDaemon
        else:
            msg = (_("Got unknown daemon: %s") % daemon_name)
            raise OTPmeException(msg)

        try:
            daemon = daemon_class(daemon_name, daemon_user, daemon_group)
        except Exception as e:
            msg = ("Unable to load daemon class: %s: %s" % (daemon_class, e))
            self.logger.critical(msg)
            config.raise_exception()
            return

        try:
            add_result = self.add_child(daemon, reload=reload,
                                        master_node=master_node)
        except Exception as e:
            msg = "Failed to start child daemon: %s: %s" % (daemon.name, e)
            add_result = False

        return add_result

    def ensure_daemons(self):
        for x in self.daemons:
            if self.ensure_daemon(x):
                continue
            return False
        return True

    def ensure_daemon(self, daemon_name):
        """ Make sure given daemon is running. """
        retry = config.controld_heartbeat_retry
        retry_interval = config.controld_heartbeat_retry_interval
        heartbeat_timeout = config.controld_heartbeat_timeout

        # Try to get daemon instance.
        daemon = self.get_child(daemon_name)

        if not daemon:
            self.logger.debug("Starting %s" % daemon_name)
            self.start_daemon(daemon_name)
            return True

        # Do not send heartbeat to some daemons.
        if daemon_name in self.no_heartbeat_daemons:
            return True

        retry_count = 0
        while True:
            retry_count += 1
            # Send heartbeat message.
            try:
                self.comm_handler.send(daemon_name, command="ping")
                self.childs[daemon_name]['status'] = "ping"
                heartbeat_sent = True
            except Exception as e:
                msg = ("Unable to send heartbeat packet to: %s" % daemon_name)
                self.logger.critical(msg, exc_info=True)
                heartbeat_sent = False

            if heartbeat_sent:
                # Try to get heartbeat reply.
                try:
                    sender, \
                    ping_reply, \
                    data = self.comm_handler.recv(sender=daemon_name,
                                            timeout=heartbeat_timeout)
                except TimeoutReached:
                    ping_reply = None
                except ExitOnSignal:
                    break
                except Exception as e:
                    msg = ("Failed to receive heartbeat reply: %s: %s"
                            % (daemon_name, type(e)))
                    self.logger.critical(msg, exc_info=True)
                    ping_reply = None
                # Check for heartbeat reply.
                if ping_reply:
                    #if ping_reply == "down":
                    #    return
                    #if ping_reply == "quit":
                    #    return
                    if ping_reply == "pong":
                        daemon_status = "ready"
                    else:
                        msg = ("Got wrong response to heartbeat packet from daemon "
                                "'%s': %s" % (daemon_name, ping_reply))
                        raise OTPmeException(msg)
                    self.childs[daemon_name]['status'] = daemon_status
                    return True

            if retry == retry_count:
                msg = ("Daemon '%s' is not responding. Trying to restart..."
                        % daemon_name)
                self.logger.critical(msg)
                self.stop_child(daemon_name)
                self.start_daemon(daemon_name)
                return False

            msg = ("Daemon '%s' is not responding. Retrying in %s seconds..."
                    % (daemon_name, retry_interval))
            self.logger.critical(msg)
            time.sleep(retry_interval)

    def _reload(self):
        """ Daemon reload. """
        self.logger.info("Starting config reload...")
        # Set our status to config loading to prevent another
        # SIGTERM to initiate another reload which may confuse us.
        self.loading = True
        # Reload config.
        config.reload()
        # Re-init.
        init_otpme()
        # Check for config changes.
        try:
            self.configure()
            restart_childs = False
        except DaemonRestart:
            restart_childs = True

        if self.need_restart:
            restart_childs = True
            self.need_restart = False

        if restart_childs:
            self.stop_all_childs()
            for x in self.childs:
                self.start_daemon(x)
        else:
            # Reload child daemons.
            # Send reload command to child daemons.
            for x in self.daemons:
                self._reload_child(x)

        # Reload DB.
        self._reload_index()

        # Reset variables.
        self.loading = False
        self.logger.info("Finished config reload...")

    def _reload_child(self, daemon_name):
        """ Send reload command to child daemon. """
        msg = ("Sending reload command to child daemon: %s"
                % daemon_name)
        self.logger.info(msg)
        self.childs[daemon_name]['status'] = "reload"
        try:
            self.comm_handler.send(recipient=daemon_name, command="reload")
        except Exception as e:
            msg = ("Unable to send reload signal to: %s: %s"
                    % (daemon_name, e))
            self.logger.critical(msg)

        # Max wait for child daemon reload.
        max_wait = 15
        count_wait = 0
        # Wait until we get 'reload_done' reply from child daemon.
        while True:
            if count_wait == max_wait:
                msg = ("Child daemon '%s' does not respond to "
                        "reload command. Restarting..."
                        % daemon_name)
                self.logger.info(msg)
                self.stop_child(daemon_name)
                self.start_daemon(daemon_name)
                break
            try:
                sender, reply, data = self.comm_handler.recv(sender=daemon_name,
                                                                timeout=0.01)
            except TimeoutReached:
                continue
            except ExitOnSignal:
                break
            except Exception as e:
                msg = ("Failed to get daemon reload reply: %s: %s"
                        % (daemon_name, e))
                self.logger.critical(msg, exc_info=True)
                continue

            if reply == "reload_shutdown":
                msg = ("Child daemon '%s' needs a restart to "
                        "reload its config." % daemon_name)
                self.logger.info(msg)
                master_node = config.master_node
                self.stop_child(daemon_name)
                self.start_daemon(daemon_name, reload=True,
                                master_node=master_node)
                break
            if reply == "reload_done":
                self.childs[sender]['status'] = "ready"
                break

    def add_child(self, daemon, reload=False, master_node=False):
        """ Start a child daemon and add it to self.childs dictionary. """
        # We must use the sync manager here to get a successful daemon shutdown.
        comm_handler = self.comm_queue.get_handler(daemon.name)

        # Add reload kwarg to daemon start.
        target_kwargs = {'reload':reload, 'master_node':master_node}

        # Create process instance.
        p = multiprocessing.start_process(name=daemon.name,
                                        target=daemon.run,
                                        target_args=(comm_handler,),
                                        target_kwargs=target_kwargs)
        startup_timeout = 15
        try:
            sender, \
            reply, \
            data = self.comm_handler.recv(sender=daemon.name,
                                        timeout=startup_timeout)
        except Exception as e:
            msg = ("Error getting startup response from %s: %s"
                            % (daemon.name, e))
            self.logger.critical(msg, exc_info=True)
            return False

        if reply == "ready":
            daemon_status = reply
            msg = ("Got 'ready' message from %s." % daemon.name)
            self.logger.info(msg)
        else:
            daemon_status = False
            msg = "Error starting %s: Wrong reply: %s" % (daemon.name, reply)
            self.logger.critical(msg)

        if daemon_status is False:
            return

        # Add daemon instance and queues used for communication to shared
        # dictionary.
        self.childs[daemon.name] = {
                            'status'    : 'running',
                            'instance'  : p,
                            }

        return daemon_status

    def get_child(self, child_name):
        """ Get child daemon process. """
        try:
            daemon = self.childs[child_name]['instance']
        except:
            return
        return daemon

    def stop_child(self, daemon_name):
        """ Stop child daemon. """
        terminate_wait = 10000
        # Get child daemon process.
        daemon = self.get_child(daemon_name)
        if not daemon:
            return
        msg = ("Waiting for child daemon '%s (%s)' to shutdown."
                    % (daemon_name, daemon.pid))
        self.logger.info(msg)
        # Send quit to child daemon.
        #self.comm_handler.send(recipient=daemon.name, command="quit")
        try:
            stuff.kill_pid(daemon.pid)
        except Exception as e:
            msg = ("Failed to send SIGTERM to daemon '%s (%s)': %s"
                    % (daemon.name, daemon.pid, e))
            self.logger.warning(msg)

        # Wait until we get 'down' reply from child daemon or it dies.
        count = 0
        while daemon.is_alive():
            if count == terminate_wait:
                msg = ("Child daemon '%s (%s)' ignored SIGTERM "
                                "command. Sending SIGKILL."
                                % (daemon_name, daemon.pid))
                self.logger.warning(msg)
                try:
                    stuff.kill_pid(daemon.pid,
                                recursive=True,
                                timeout=self.daemon_msg_timeout)
                except Exception as e:
                    msg = ("Failed to send SIGKILL to daemon '%s (%s)': %s"
                            % (daemon.name, daemon.pid, e))
                    self.logger.warning(msg)
                break

            time.sleep(0.001)
            count += 1

        # Join child daemon process.
        daemon.join()

        msg = ("Child daemon '%s' shutdown succeeded." % daemon_name)
        self.logger.info(msg)

    def stop_all_childs(self):
        """ Stop all child daemons. """
        for daemon in reversed(self.daemons):
            self.stop_child(daemon)
