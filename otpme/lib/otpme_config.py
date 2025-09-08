# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import sys
import time
import copy
import gettext
import datetime
import importlib
import collections

if "OTPME_DEBUG_MODULE_LOADING" not in os.environ:
    os.environ['OTPME_DEBUG_MODULE_LOADING'] = "False"
if "OTPME_DEBUG_NEED_DECORATOR" not in os.environ:
    os.environ['OTPME_DEBUG_NEED_DECORATOR'] = "False"
if "OTPME_DEBUG_FILE_READ" not in os.environ:
    os.environ['OTPME_DEBUG_FILE_READ'] = "False"
if "OTPME_DEBUG_FILE_WRITE" not in os.environ:
    os.environ['OTPME_DEBUG_FILE_WRITE'] = "False"

if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
    print("Loading module: %s" % __name__)

import otpme
from otpme.lib import re
from otpme.lib import log
from otpme.lib.messages import message
from otpme.lib.encryption import get_module
from otpme.lib.messages import error_message

from otpme.lib.exceptions import *

class OTPmeConfig(object):
    def __init__(self, tool_name="otpme", use_syslog=False,
        use_systemd_log=False, auto_load=True, quiet=False):
        # All registered methods.
        self.methods = []
        # All registered properties.
        self.properties = []
        # All registered extensions.
        self.extensions = []
        self.default_extensions = {}
        self.dn_attributes = {}
        # Method hooks to be handled by auth_on_action policy.
        self.auth_on_action_hooks = {}
        # Valid config parameter than can be added to objects
        # (register_config_parameter()).
        self.valid_config_params = {}
        self.default_policies = {}
        self.configfile_var_map = {}
        self.user_configfile_var_map = {}
        self.user_configfile_params = []
        self.merge_user_configfile_params = []
        self._post_register_methods = []
        # Valid config variables and their type.
        self.config_var_types = {}
        # Main config file parameters.
        self.register_config_var("main_config", dict, None)
        # User config file path.
        self.register_config_var("user_conf_file", str, None)
        # Directory to store user specific signers (public keys).
        self.register_config_var("user_signers_dir", str, None)
        # Our pid.
        self.register_config_var("my_pid", int, None)
        # Our host type.
        self.register_config_var("host_type", str, None)
        # Add objects in this order (e.g. on sync).
        self.register_config_var("_object_add_order", dict, {})
        # Receive objects in this order (e.g. on sync).
        self.register_config_var("_object_sync_order", dict, {})
        # Sync status stuff.
        self.register_config_var("SYNCING_STATUS_STRING", str, "SYNCING")
        self.register_config_var("SYNC_STATUS_LOCK_TYPE", str, "sync_status")
        # Node sync lock type.
        self.register_config_var("NODE_SYNC_LOCK_TYPE", str, "node_sync")
        # Data revision update lock type
        self.register_config_var("DATA_REVISION_LOCK_TYPE", str, "data_revision_update")
        # Set tool and log name.
        self.register_config_var("tool_name", str, tool_name)
        #self.register_config_var("log_name", str, "otpme")

        self.register_config_var("my_name", str, "OTPme")
        self.register_config_var("my_version", str, otpme.__version__)
        # Get python version.
        self.register_config_var("py_version", tuple, tuple(sys.version_info))
        # PAM log settings.
        self.register_config_var("pam_use_syslog", bool, False,
                            config_file_parameter="PAM_USE_SYSLOG")
        self.register_config_var("pam_use_systemd", bool, False,
                            config_file_parameter="PAM_USE_SYSTEMD")
        self.register_config_var("pam_use_logfile", bool, False,
                            config_file_parameter="PAM_USE_LOGFILE")
        self.register_config_var("pam_logfile", str, "/var/log/otpme/pam.log",
                            config_file_parameter="PAM_LOGFILE")
        # Pickle type to use for caching.
        self.register_config_var("pickle_cache_module", str, "pickle",
                                config_file_parameter="PICKLE_CACHE_MODULE")
        # Default OTPme user/group.
        self.register_config_var("user", str, "otpme",
                            config_file_parameter="USER")
        self.register_config_var("group", str, "otpme",
                            config_file_parameter="GROUP")
        self.register_config_var("offline_methods", dict, {})
        # Hash type to derive offline token encryption key from password.
        self.register_config_var("offline_token_hash_type", str, "Argon2_i",
                                config_file_parameter="OFFLINE_TOKEN_HASH_TYPE",
                                user_config_file_parameter="OFFLINE_TOKEN_HASH_TYPE")
        # Hash type to derive object export encryption key from password.
        self.register_config_var("object_export_hash_type", str, "Argon2_i",
                                config_file_parameter="OBJECT_EXPORT_HASH_TYPE",
                                user_config_file_parameter="OBJECT_EXPORT_HASH_TYPE")
        # Default pinentry.
        self.register_config_var("pinentry", str, "/usr/bin/pinentry",
                                config_file_parameter="PINENTRY",
                                user_config_file_parameter="PINENTRY")
        # LDAP verify ACLs.
        self.register_config_var("ldap_verify_acls", bool, False,
                                config_file_parameter="LDAP_VERIFY_ACLS")
        self.register_config_var("_logger", None, None)
        # Index type to use.
        self.register_config_var("index_type", str, "postgres",
                                config_file_parameter="INDEX")
        self.register_config_var("cache_type", str, "redis",
                                config_file_parameter="CACHE")
        # Start/stop index DB on daemon start.
        self.register_config_var("autostart_index", bool, True,
                            config_file_parameter="AUTOSTART_INDEX")
        # Start/stop cache on daemon start.
        self.register_config_var("autostart_cache", bool, True,
                            config_file_parameter="AUTOSTART_CACHE")
        # Flush cache on daemon start.
        self.register_config_var("flush_cache_on_start", bool, True,
                            config_file_parameter="FLUSH_CACHE_ON_START")
        # Max posix message queue size.
        self.register_config_var("rlimit_msgqueue", int, 2621440000,
                            config_file_parameter="RLIMIT_MSGQUEUE")
        # Max posix message queue message size.
        self.register_config_var("_posix_msgsize_max", None, 8192,
                            config_file_parameter="POSIX_MSGSIZE_MAX")
        self.register_config_var("posix_msgsize_max", None, 8192)
        # Socket receive buffer.
        self.register_config_var("socket_receive_buffer", int, 104857600,
                            config_file_parameter="SOCKET_RECEIVE_BUFFER")
        # Realm infos.
        self.register_config_var("realm", str, None)
        self.register_config_var("realm_uuid", str, None)
        # Site infos.
        self.register_config_var("site", str, None)
        self.register_config_var("site_uuid", str, None)
        self.register_config_var("site_auth_fqdn", str, None)
        self.register_config_var("site_mgmt_fqdn", str, None)
        self.register_config_var("site_address", str, None)

        # Users otpme config.
        self.register_config_var("user_config", dict, None)
        # Indicates config reload.
        self.register_config_var("config_reload", bool, None)
        self.register_config_var("user_config_reload", bool, None)

        self.register_config_var("handle_files_dirs", bool, True,
                                config_file_parameter="HANDLE_FILES_DIRS")
        self.register_config_var("last_config_file_checksum", str, None)
        self.register_config_var("last_user_config_file_checksum", str, None)

        self.register_config_var("log_filter", list, [])
        self.register_config_var("loglevel", str, "INFO",
                            config_file_parameter="LOGLEVEL")
        self.register_config_var("color_logs", bool, False)
        self.register_config_var("log_auth_data", [bool, list], False,
                                config_file_parameter="LOG_AUTH_DATA")

        # Indicates an ongoing realm init.
        self.register_config_var("realm_init", bool, False)
        # Indicates an ongoing site init.
        self.register_config_var("site_init", bool, False)
        # Indicates an ongoing realm join.
        self.register_config_var("realm_join", bool, False)
        # Indicates caching is enabled.
        self.register_config_var("cache_enabled", bool, False)
        # Indicates if locking is enabled.
        self.register_config_var("locking_enabled", bool, True)
        # Indicates typing is enabled.
        self.register_config_var("typing_enabled", bool, False)
        # Job timeout.
        self.register_config_var("job_timeout", int, 60)
        # Active (committing) transactions prevent jobs from being stopped.
        self.register_config_var("active_transactions", list, [])

        self.register_config_var("command_handler", None, None)
        self.register_config_var("command_line_opts", list, [])

        self.register_config_var("print_raw_sign_data", bool, False)
        self.register_config_var("add_job_id_to_proctitle", bool, False,
                                config_file_parameter="SHOW_JOB_TITLE")

        self.register_config_var("disk_encryption", str, "FERNET")
        self.register_config_var("disk_encryption_mod", object, None)

        self.register_config_var("cli_object_type", str, "main")

        # Force operation (-f).
        self.register_config_var("force", bool, False)
        # Indicates we run in daemon mode.
        self.register_config_var("daemon_mode", bool, False)
        # Daemon we are running at.
        self.register_config_var("daemon_name", str, None)
        # Global connect timeout (-t).
        self.register_config_var("connect_timeout", int, 5)
        # Global connection timeout (-tt).
        self.register_config_var("connection_timeout", int, 15)
        # Session reneg timeout (--reneg-timeout).
        self.register_config_var("reneg_timeout", int, 30)
        self.register_config_var("daemons", list, [])

        # Inter-daemon communication timeout.
        self.register_config_var("inter_daemon_comm_timeout", int, 2,
                            config_file_parameter="INTER_DAEMON_COMM_TIMEOUT")
        self.register_config_var("controld_heartbeat_interval", int, 15,
                                config_file_parameter="CONTROLD_HEARTBEAT_INTERVAL")
        self.register_config_var("controld_heartbeat_retry_interval", int, 3,
                            config_file_parameter="CONTROLD_HEARTBEAT_RETRY_INTERVAL")
        self.register_config_var("controld_heartbeat_timeout", int, 15,
                                config_file_parameter="CONTROLD_HEARTBEAT_TIMEOUT")
        self.register_config_var("controld_heartbeat_retry", int, 3,
                            config_file_parameter="CONTROLD_HEARTBEAT_RETRY")

        self.register_config_var("agent_connection_idle_timeout", int, 300,
                        config_file_parameter="AGENT_CONNECTION_IDLE_TIMEOUT")
        self.register_config_var("agent_keepalive_interval", int, 6,
                                config_file_parameter="AGENT_KEEPALIVE_INTERVAL")

        self.register_config_var("sync_mem_cache", bool, True,
                            config_file_parameter="SYNC_MEM_CACHE")

        # Use DNS to get OTPme login realm/site and socket URI.
        self.register_config_var("login_use_dns", bool, True,
                                config_file_parameter="LOGIN_USE_DNS")
        # Use DNS to get OTPme site address.
        self.register_config_var("use_dns", bool, False,
                            config_file_parameter="USE_DNS")
        # Use direct API calls instead of connecting to the daemons.
        self.register_config_var("use_api", bool, False)
        # Emulate login token when running in API mode.
        self.register_config_var("api_auth_token", None, None)
        # Use a running ssh-agent for authentication with daemons.
        self.register_config_var("use_ssh_agent", None, "auto")
        # Use a connected smartcard for authentication with daemons.
        self.register_config_var("use_smartcard", None, "auto")
        # Read password from stdin.
        self.register_config_var("read_stdin_pass", bool, False)
        # Password read from stdin.
        self.register_config_var("stdin_pass", str, None)
        # Locking stuff.
        self.register_config_var("lock_timeout", int, 30)
        self.register_config_var("lock_wait_timeout", int, 0)
        # Ignore if objects change while waiting for lock.
        self.register_config_var("ignore_changed_objects", bool, False)
        # Use direct backend access (e.g. in daemon mode).
        self.register_config_var("use_backend", None, None)
        # Debug mode.
        self.register_config_var("debug_enabled", bool, False)
        self.register_config_var("debug_levels", dict, {})
        # The user name of the current process. We need this
        # to e.g. debug timings while users logs in when auth user
        # is not yet set.
        self.register_config_var("debug_user", str, None)
        # The users debugging is enabled for (e.g. show method timings).
        self.register_config_var("debug_users", list, [])
        # The daemons debugging is enabled for (e.g. show method timings).
        self.register_config_var("debug_daemons", list, [])
        # The sorting field for cProfile.
        self.register_config_var("debug_profile_sort", str, "cumtime")
        # The functions debug timing is enabled for.
        self.register_config_var("debug_func_names", list, [])
        # The function debug timing starts at.
        self.register_config_var("debug_func_start", list, [])
        # The function caches debugging is enabled for.
        self.register_config_var("debug_func_caches", list, [])
        # Start daemon in background.
        self.register_config_var("daemonize", bool, True)
        # Be verbose.
        self.register_config_var("verbose_level", int, 0)
        # Limit a function/method must at least take to be printed.
        self.register_config_var("debug_timing_limit", float, 0.2)
        self.register_config_var("debug_counter_limit", int, 100)
        # Print warning if function/method call took longer than debug timing limit.
        self.register_config_var("print_timing_warnings", bool, False)
        # Print result of function/method calls that took longer than debug timing limit.
        self.register_config_var("print_timing_results", bool, False)
        # Print each time a method gets slower.
        self.register_config_var("print_method_slowness", bool, False)
        # Print tracebacks.
        self.register_config_var("print_tracebacks", bool, None,
                                config_file_parameter="TRACEBACKS")
        # Keep floating IP address on daemon stop.
        self.register_config_var("keep_floating_ip", bool, False)
        # Enable logging via syslog.
        self.register_config_var("use_syslog", bool, use_syslog)
        # Enable logging via systemd-journald.
        self.register_config_var("use_systemd_log", bool, use_systemd_log)
        # Enable logging to file.
        self.register_config_var("file_logging", bool, False)
        # Path to logfile.
        self.register_config_var("log_file", str, None)
        # Override logfile path (-l).
        self.register_config_var("force_logfile", None, None)
        # Host UUID.
        self.register_config_var("uuid", str, None)
        ## OID locking is required with sqlite index.
        #self.register_config_var("oid_locking_enabled", bool, False)

        # Raise exceptions in debug mode.
        self.register_config_var("raise_exceptions", bool, False)

        # Master key we need to en-/decrypt sensitive config data.
        self.register_config_var("master_key", str, None)
        # Salt used when hashing passwords.
        self.register_config_var("password_hash_salt", str, None)
        # Cluster key used to secure cluster communication.
        self.register_config_var("cluster_key", str, None)
        # Wait for objects to be written to cluster nodes.
        self.register_config_var("wait_for_cluster_writes", bool, True)

        # Realm/site we connect to (-r/-s)
        self.register_config_var("connect_realm", str, None)
        self.register_config_var("connect_site", str, None)
        # Base CA paths.
        #self.register_config_var("realm_ca_path", str, None)
        #self.register_config_var("site_ca_path", str, None)
        # Users (instance) of the authenticated user.
        self.register_config_var("auth_user", None, None)
        # Users token (instance) that was used to authenticate the user of the current
        # connection.
        self.register_config_var("auth_token", None, None)
        # Which auth type the user authenticated (e.g. sotp)
        self.register_config_var("auth_type", None, None)
        # Token with realm admin rights.
        self.register_config_var("admin_token_uuid", str, None)
        # OTPme site admin role UUID.
        self.register_config_var("admin_role_uuid", str, None)
        # OTPme realm users group UUID.
        self.register_config_var("realm_users_group_uuid", str, None)
        # Run root scripts as this user.
        self.register_config_var("root_script_user", str, "nobody",
                            config_file_parameter="ROOT_SCRIPT_USER")
        self.register_config_var("root_script_group", str, "nogroup",
                            config_file_parameter="ROOT_SCRIPT_GROUP")

        # Policy ignore stuff.
        self.register_config_var("ignore_policy_types", list, [])
        self.register_config_var("ignore_policy_tags", list, [])
        # Backend policy stuff.
        self.register_config_var("backend_policy_interval", int, 60,
                            config_file_parameter="BACKEND_POLICY_INTERVAL")
        # hostd sync interval in seconds.
        self.register_config_var("hostd_sync_interval", int, 300,
                                config_file_parameter="SYNC_INTERVAL")
        # To prevent our local objects from beeing in an inconsistent state (e.g. token
        # is synced but not its second factor token) we need to be in an consistent
        # state with the master node at least at one point while doing a sync. The
        # hostd sync retry count paramter configures how many times we will try to get
        # a consistent state until we wait for hostd sync interval before retrying.
        self.register_config_var("hostd_sync_retry_count", int, 5,
                                config_file_parameter="SYNC_RETRY_COUNT")
        # Retry interval if sync failed (e.g. network problems) in seconds.
        self.register_config_var("hostd_sync_retry_interval", int, 10,
                                config_file_parameter="SYNC_RETRY_INTERVAL")
        # Ignore if objects changed while syncing.
        self.register_config_var("hostd_sync_ignore_changed_objects", bool, False,
                            config_file_parameter="SYNC_IGNORE_CHANGED_OBJECTS")

        # Object types that are in tree.
        # The order of this list is important (e.g. for signature tags)
        self.register_config_var("tree_object_types", list, [])
        # Object types that are out of tree.
        self.register_config_var("flat_object_types", list, [])
        # All object types.
        self.register_config_var("object_types", list, [])
        # All sub object types (e.g. token types).
        self.register_config_var("sub_object_types", dict, {})
        # Object is a backend object.
        self.register_config_var("backend_object_types", list, [])
        # Objects that can be uniquely identified by their name.
        self.register_config_var("name_uniq_objects", list, [])
        # Attributes to build backup filename.
        self.register_config_var("backup_attributes", dict, {})
        # LDAP object types.
        self.register_config_var("ldap_object_types", dict, {})

        # Objects we cache and their limit.
        self.register_config_var("cache_objects", dict, {})

        # Cache regions for function and dogpile caches.
        self.register_config_var("cache_regions", dict, {})

        # Will filled with valid attribute types for each extension/object.
        self.register_config_var("attribute_types", dict, {})

        # xxxxxxxx
        # FIXME: add config file parameter?
        # Some base dirs.
        self.register_config_var("tmp_dir", str, "/tmp")
        self.register_config_var("bin_dir", str, "/usr/local/bin",
                                config_file_parameter="BIN_DIR")

        self.register_config_var("data_dir", str, "/var/lib/otpme",
                                config_file_parameter="DATA_DIR")
        self.register_config_var("spool_dir", str, "/var/spool/otpme",
                                config_file_parameter="SPOOL_DIR")
        self.register_config_var("cache_dir", str, "/var/cache/otpme",
                                config_file_parameter="CACHE_DIR")
        self.register_config_var("run_dir", str, "/var/run/otpme",
                                config_file_parameter="RUN_DIR")
        self.register_config_var("log_dir", str, "/var/log/otpme",
                                config_file_parameter="LOG_DIR")
        self.register_config_var("mount_root_dir", str, "/otpme",
                                config_file_parameter="MOUNT_ROOT_DIR")

        # Set some default filenames.
        self.register_config_var("config_file_name", str, None)
        self.config_file_name = "%s.conf" % self.my_name.lower()
        self.register_config_var("uuid_file_name", str, None)
        self.uuid_file_name = "%s.uuid" % self.my_name.lower()
        self.register_config_var("master_pass_salt_file_name", str, None)
        self.master_pass_salt_file_name = "%s.key_salt" % self.my_name.lower()
        self.register_config_var("password_hash_salt_file_name", str, None)
        self.password_hash_salt_file_name = "%s.pass_salt" % self.my_name.lower()

        # Set some default file paths.
        self.register_config_var("config_dir", str, None)
        self.config_dir = os.path.join("/etc", self.my_name.lower())
        self.register_config_var("config_file", str, None)
        self.config_file = os.path.join(self.config_dir, self.config_file_name)
        self.register_config_var("uuid_file", str, None)
        self.uuid_file = os.path.join(self.config_dir, self.uuid_file_name)
        self.register_config_var("master_pass_salt_file", str, None)
        self.master_pass_salt_file = os.path.join(self.config_dir, self.master_pass_salt_file_name)
        self.register_config_var("password_hash_salt_file", str, None)
        self.password_hash_salt_file = os.path.join(self.config_dir, self.password_hash_salt_file_name)
        self.register_config_var("signers_dir", str, None)
        self.signers_dir = os.path.join(self.config_dir, "signers")

        self.register_config_var("otpme_lib_dir", str, None)
        self.otpme_lib_dir = str(os.path.dirname(__file__))
        self.register_config_var("base_dir", str, None)
        self.base_dir = os.path.dirname(self.otpme_lib_dir)
        self.register_config_var("locale_dir", str, None)
        self.locale_dir = os.path.join(self.base_dir, "locale")
        self.register_config_var("extensions_dir", str, None)
        self.extensions_dir = os.path.join(self.otpme_lib_dir, "extensions")
        self.register_config_var("token_dir", str, None)
        self.token_dir = os.path.join(self.otpme_lib_dir, "token")
        #self.register_config_var("smartcard_dir", str, None)
        #self.smartcard_dir = os.path.join(self.otpme_lib_dir, "smartcard")
        self.register_config_var("script_dir", str, None)
        self.script_dir = os.path.join(self.config_dir, "scripts")
        self.register_config_var("policy_dir", str, None)
        self.policy_dir = os.path.join(self.otpme_lib_dir, "policy")
        self.register_config_var("resolver_dir", str, None)
        self.resolver_dir = os.path.join(self.otpme_lib_dir, "resolver")
        self.register_config_var("dictionary_dir", str, None)
        self.dictionary_dir = os.path.join(self.config_dir, "dicts")
        self.register_config_var("schema_dir", str, None)
        self.schema_dir = os.path.join(self.config_dir, "schema")

        # Some dirs are set after reading the config (their parent dir).
        self.register_config_var("locks_dir", str, None)
        self.register_config_var("pidfile_dir", str, None)
        self.register_config_var("sockets_dir", str, None)
        self.register_config_var("sync_dir", str, None)
        self.register_config_var("reload_file_path", str, None)
        self.register_config_var("node_sync_file", str, None)
        self.register_config_var("cache_clear_file", str, None)
        self.register_config_var("node_joined_file", str, None)
        self.register_config_var("realm_data_file_path", str, None)
        self.register_config_var("sync_status_file_path", str, None)
        self.register_config_var("offline_dir", str, None)
        self.register_config_var("env_dir", str, None)
        self.register_config_var("nsscache_dir", str, None)
        self.register_config_var("sign_key_cache_dir", str, None)
        self.register_config_var("ssh_deploy_dir", str, None)
        self.register_config_var("authorized_keys_dir", str, None)
        self.register_config_var("nsscache_spool_dir", str, None)
        self.register_config_var("nsscache_objects_dir", str, None)
        self.register_config_var("transaction_dir", str, None)

        ssl_dir = os.path.join(self.config_dir, "ssl")
        self.register_config_var("ssl_dir", str, ssl_dir)
        ssl_key_file = os.path.join(self.ssl_dir, "key.pem")
        self.register_config_var("ssl_key_file", str, ssl_key_file,
                                config_file_parameter="SSL_KEY_FILE")
        ssl_cert_file = os.path.join(self.ssl_dir, "cert.pem")
        self.register_config_var("ssl_cert_file", str, ssl_cert_file,
                                config_file_parameter="SSL_CERT_FILE")
        ssl_ca_file = os.path.join(self.ssl_dir, "ca.pem")
        self.register_config_var("ssl_ca_file", str, ssl_ca_file,
                                config_file_parameter="SSL_CA_FILE")
        ssl_site_cert_file = os.path.join(self.ssl_dir, "site_cert.pem")
        self.register_config_var("ssl_site_cert_file", str, ssl_site_cert_file,
                                config_file_parameter="SSL_SITE_CERT_FILE")
        host_key_file = os.path.join(self.ssl_dir, "hostkey.pem")
        self.register_config_var("host_key_file", str, host_key_file,
                                config_file_parameter="HOST_KEY_FILE")

        self.register_config_var("nsscache_sync_file", str, None)

        self.register_config_var("nsscache_pidfile", str, None)

        self.register_config_var("controld_pidfile", str, None)
        self.register_config_var("authd_socket_path", str, None)
        self.register_config_var("hostd_socket_path", str, None)
        self.register_config_var("clusterd_socket_path", str, None)
        self.register_config_var("key_command", str, None,
                                config_file_parameter="KEY_COMMAND")
        self.register_config_var("master_key_hash_type", str, "Argon2_i",
                                config_file_parameter="MASTER_KEY_HASH_TYPE")
        # Compress object JSON files.
        self.register_config_var("object_json_compression", str, None,
                                config_file_parameter="OBJECT_JSON_COMPRESSSION")
        # Prettify object JSON.
        self.register_config_var("prettify_object_json", bool, False,
                                config_file_parameter="PRETTIFY_OBJECT_JSON")

        # FIXME: where to configure this?
        # Index journal settings.
        self.register_config_var("index_journal_max", int, 128)

        # All base objects.
        self.register_config_var("base_objects", dict, {})
        # Default units of objects.
        self.register_config_var("default_units", dict, {})
        # All internal objects.
        self.register_config_var("internal_objects", dict, {})
        # All supported smartcard types.
        self.register_config_var("supported_smartcards", dict, {})
        # Timeout for second node to appear in two node clusters.
        self.register_config_var("two_node_timeout", int, 30,
                            config_file_parameter="TWO_NODE_TIMEOUT")

        self.register_config_var("per_site_objects", dict, {})
        self.register_config_var("object_templates", dict, {})

        self.register_config_var("force_token_signers", [None, list], None,
                                config_file_parameter="FORCE_TOKEN_SIGNERS")
        self.register_config_var("force_key_script_signers", [None, list], None,
                            config_file_parameter="FORCE_KEY_SCRIPT_SIGNERS")
        self.register_config_var("force_agent_script_signers", [None, list], None,
                            config_file_parameter="FORCE_AGENT_SCRIPT_SIGNERS")

        # Signer types a normal user is allowed to add. This applies
        # to any signature type that is checked on the client computer.
        valid_private_signer_types = [
                                    'token',
                                    'key_script',
                                    'agent_script',
                                    ]
        self.register_config_var("valid_private_signer_types", list, valid_private_signer_types)

        self.register_config_var("_login_user", str, None)

        self.register_config_var("deny_login_users", [None, list], None,
                                config_file_parameter="DENY_LOGIN_USERS")
        self.register_config_var("valid_login_users", [None, list], None,
                                config_file_parameter="VALID_LOGIN_USERS")

        self.register_config_var("object_caches", [None, list], None,
                                config_file_parameter="OBJECT_CACHES")

        default_ports = {
                    'authd'     : '2020',
                    'hostd'     : '2021',
                    'mgmtd'     : '2022',
                    'syncd'     : '2023',
                    'joind'     : '2024',
                    'clusterd'  : '2025',
                    'ldapd'     : '2026',
                    'fsd'       : '2027',
                    }
        self.register_config_var("default_ports", dict, default_ports)

        default_listen_ports = {
                    'authd'     : '2020',
                    'hostd'     : '2021',
                    'mgmtd'     : '2022',
                    'syncd'     : '2023',
                    'joind'     : '2024',
                    'clusterd'  : '2025',
                    'ldapd'     : '2026',
                    'fsd'       : '2027',
                    }
        self.register_config_var("default_listen_ports", dict, default_listen_ports)

        self.register_config_var("listen_sockets", dict, {})

        # OTPme base attributes that are directly assigned to the IndexObject().
        otpme_base_attributes = [
                                'full_oid',
                                'read_oid',
                                'oid',
                                'uuid',
                                'realm',
                                'site',
                                'name',
                                'path',
                                'rel_path',
                                'checksum',
                                'sync_checksum',
                                'template',
                                'ldif',
                                'object_type',
                                'last_used',
                                #'acl',
                                #'enabled',
                                #'resolver',
                                #'resolver_key',
                                #'resolver_checksum',
                                #'create_time',
                                #'last_modified',
                                ]
        self.register_config_var("otpme_base_attributes", list, otpme_base_attributes)
        # Additional OTPme attributes.
        self.register_config_var("otpme_index_attributes", list, [])
        # LDAP attributes that should be added to the (file backend) attribute index.
        self.register_config_var("ldap_index_attributes", list, [])
        # All index attributes.
        self.register_config_var("index_attributes", list, [])

        self.register_config_var("logout_pass_len", int, 6,
                            config_file_parameter="LOGOUT_PASS_LEN")
        self.register_config_var("node_jotp_len", int, 8)
        self.register_config_var("host_jotp_len", int, 8)
        self.register_config_var("join_jotp_hash_type", str, "PBKDF2")
        self.register_config_var("join_lotp_hash_type", str, "PBKDF2")

        self.register_config_var("object_config_file_name", str, "object.json")

        # FIXME: make this a (user) config file option?
        self.register_config_var("pwgen", str, "pwgen")
        self.register_config_var("agent_vars_filename", str, ".ssh_agent_vars")

        valid_token_login_interfaces = [
                                        'gui',
                                        'tty',
                                        'ssh',
                                    ]
        self.register_config_var("valid_token_login_interfaces",
                                list, valid_token_login_interfaces)

        self.register_config_var("last_config_file_mtime", float, 0.0)
        self.register_config_var("last_reload_file_mtime", float, 0.0)
        self.register_config_var("last_config_reload_check", float, 0.0)

        self.register_config_var("reload_config_interval", int, 60,
                                config_file_parameter="RELOAD_CONFIG_INTERVAL")

        self.register_config_var("supported_protocols", dict, {})
        self.register_config_var("supported_encryption_types", dict, {})
        self.register_config_var("supported_encoding_types", dict, {})
        self.register_config_var("supported_compression_types", dict, {})
        self.register_config_var("supported_hash_types", dict, {})
        self.register_config_var("supported_ecdh_curves", dict, {})

        self.register_config_var("sync_object_types", dict, {})
        self.register_config_var("cluster_object_types", list, [])

        self.register_config_var("use_radius_mod", bool, True,
                            config_file_parameter="USE_RADIUS_MOD")

        self.register_config_var("radius_cache_time", int, 60,
                            config_file_parameter="RADIUS_CACHE_TIME")

        self.register_config_var("radius_start_servers", int, 32,
                            config_file_parameter="RADIUS_START_SERVERS")
        self.register_config_var("radius_max_servers", int, 64,
                            config_file_parameter="RADIUS_MAX_SERVERS")
        self.register_config_var("radius_min_spare_servers", int, 8,
                            config_file_parameter="RADIUS_MIN_SPARE_SERVERS")
        self.register_config_var("radius_max_spare_servers", int, 16,
                            config_file_parameter="RADIUS_MAX_SPARE_SERVERS")

        self.register_config_var("radius_mod_logfile", str, "/var/log/otpme/radius-module.log",
                            config_file_parameter="RADIUS_MOD_LOGFILE")
        self.register_config_var("start_freeradius", bool, True,
                            config_file_parameter="START_FREERADIUS")
        self.register_config_var("freeradius_bin", str, "/usr/sbin/freeradius",
                            config_file_parameter="FREERADIUS_BIN")
        self.register_config_var("pwgen_bin", str, "pwgen",
                            config_file_parameter="PWGEN")
        self.register_config_var("timezone", str, "Europe/Berlin",
                                config_file_parameter="TIMEZONE")
        # Debug stuff.
        self.register_config_var("debug_test", bool, False)

        # Set config to be imported via "from otpme.lib import config"
        otpme.lib.config = self

        # Load config etc.
        if auto_load:
            self.load(quiet=quiet)

    def __setattr__(self, name, value):
        """ Handle config variables and type checks. """
        if name == "methods":
            return object.__setattr__(self, name, value)
        if name == "properties":
            return object.__setattr__(self, name, value)
        if name in self.methods:
            return object.__setattr__(self, name, value)
        if name in self.properties:
            return object.__setattr__(self, name, value)
        if hasattr(self, name):
            return object.__setattr__(self, name, value)
        if hasattr(self, "config_var_types") and value is not None:
            try:
                var_types = self.config_var_types[name]
            except:
                msg = "Unknown config variable: %s" % name
                raise OTPmeException(msg)
            valid_value = False
            for var_type in var_types:
                if var_type is None:
                    valid_value = True
                    break
                if not isinstance(value, var_type):
                    continue
                valid_value = True
                break
            if valid_value is False:
                msg = ("Invalid value type for <%s>: Need <%s>: Got <%s>"
                        % (name, var_types, type(value)))
                raise OTPmeException(msg)
        self.__dict__[name] = value

    def process_config_file_param(self, name, val):
        """ Process config file paraemter. """
        # Get valid value types.
        try:
            val_types = self.config_var_types[name]
        except:
            msg = "Unknown config file parameter: %s" % name
            raise OTPmeException(msg)
        if list in val_types:
            if isinstance(val, str):
                if "," in val:
                    # Replace spaces before/after comma.
                    val = val.replace(" ","").split(",")
                else:
                    # Make string a list.
                    val = [val]
        return val

    @property
    def users_group(self):
        return self.site

    @property
    def log_name(self):
        # Set name for logging.
        if self.tool_name == "otpme-controld" or self.tool_name == "otpme-agent":
            if self.tool_name == "otpme-agent":
                log_name = "%s-%s" % (self.tool_name, self.system_user())
            elif self.tool_name == "otpme-controld":
                if self.daemon_name:
                    log_name = self.daemon_name
                    log_name = "%s-%s" % (self.my_name.lower(), self.daemon_name)
                else:
                    log_name = self.tool_name
        else:
            log_name = self.tool_name
        return log_name

    @property
    def object_add_order(self):
        """ Return objects in add order. """
        from otpme.lib import stuff
        order_data = dict(self._object_add_order)
        add_order = stuff.order_data_by_deps(order_data)
        return add_order

    @property
    def object_sync_order(self):
        """ Return objects in sync order. """
        from otpme.lib import stuff
        order_data = dict(self._object_sync_order)
        sync_order = stuff.order_data_by_deps(order_data)
        return sync_order

    def reload(self, quiet=False, configure_logger=False):
        """ Reload config. """
        self.config_reload = True
        # Check if user config exists (e.g. this is a config reload).
        if self.user_config:
            self.user_config_reload = True
        # Reload config.
        self.load(quiet=quiet, configure_logger=configure_logger)

    def load(self, quiet=False, configure_logger=None):
        """ Load config. """
        from otpme.lib import filetools
        from otpme.lib.register import register_module
        # Set own PID.
        self.my_pid = os.getpid()

        # Get command line options.
        if not self.config_reload:
            from otpme.lib.help import get_main_opts
            main_opts = get_main_opts()
            for var in main_opts:
                self.command_line_opts.append(var)
                val = main_opts[var]
                setattr(self, var, main_opts[var])

        # Register required modules.
        register_module("otpme.lib.filetools")
        # Register cache module before index because of dogpile dependency.
        register_module('otpme.lib.cache', ignore_deps=True)
        # Register index module after debug level was set by main opts but
        # before reading config file (index modules register config file parameters).
        register_module('otpme.lib.index', ignore_deps=True)

        # FIXME: what to do if UUID file is missing?
        # Get our UUID from file if it exists.
        if os.path.exists(self.uuid_file):
            fd = open(self.uuid_file, "r")
            self.uuid = fd.read().replace("\n", "")
            fd.close()

        # Init gettext.
        try:
            _("locale_test")
        except:
            t = gettext.translation(b'otpme', self.locale_dir, fallback=True)
            t.install()

        # Set variables from command line options.
        # Try to read main config file.
        self.main_config = self.read(quiet=quiet)

        # Merge user config parameters.
        merged_config = dict(self.main_config)
        if not self.daemon_mode:
            if self.login_user:
                # Set users signers dir.
                self.user_signers_dir = self.get_user_signers_dir(self.login_user)
                # Get user config.
                self.user_conf_file = self.get_user_conf_file(self.login_user)
                self.user_config = self.read_user_conf_file(self.user_conf_file,
                                                            quiet=quiet)
                for parameter in self.user_config:
                    if parameter not in self.merge_user_configfile_params:
                        continue
                    val = self.user_config[parameter]
                    merged_config[parameter] = val

        # Try to read index type from config.
        try:
            self.index_type = merged_config['INDEX']
        except:
            error_message("Error reading backend parameter from config file.")
            exit(1)

        # If tracebacks are not enabled by command line option try to read config
        # setting.
        if self.print_tracebacks is None:
            # Try to read traceback setting from config.
            try:
                self.print_tracebacks = merged_config['TRACEBACKS']
            except:
                # Default should be to print tracebacks.
                self.print_tracebacks = True

        # Check if we should print out tracebacks.
        if not self.print_tracebacks:
            sys.tracebacklimit = 0

        # Map config file values to variables.
        for parameter in merged_config:
            if not parameter in self.configfile_var_map:
                msg = (_("Unknown config file parameter: %s: %s")
                        % (self.config_file, parameter))
                error_message(msg)
                continue
            var = self.configfile_var_map[parameter]
            val = merged_config[parameter]
            # Ignore empty values.
            if len(str(val)) == 0:
                continue
            # Do not override command line options.
            if var in self.command_line_opts:
                continue
            # Make sure we got a valid value from config file.
            if val is not None:
                val = self.process_config_file_param(var, val)
            try:
                setattr(self, var, val)
            except Exception as e:
                msg = "Unable to set config parameter: %s: %s" % (parameter, e)
                error_message(msg)

        # Set realm/site stuff.
        if self.use_api:
            if self.connect_realm:
                self.realm = self.connect_realm
            else:
                self.connect_realm = self.realm
            if self.connect_site:
                self.site = self.connect_site
            else:
                self.connect_site = self.site
        else:
            if not self.connect_realm:
                self.connect_realm = self.realm
            if not self.connect_site:
                self.connect_site = self.site

        # Set some default values AFTER config file values are read above!
        self.pidfile_dir = os.path.join(self.run_dir, "pidfiles")
        self.sockets_dir = os.path.join(self.run_dir, "sockets")
        # Make sure we have a lock dir.
        self.locks_dir = os.path.join(self.run_dir, "locks")
        if self.daemon_mode and self.daemon_name == "agent":
            self.locks_dir = self.get_user_locks_dir(self.system_user())
        filetools.create_dir(self.locks_dir)

        self.sync_dir = os.path.join(self.spool_dir, "sync")
        self.reload_file_path = os.path.join(self.spool_dir, "reload")
        self.node_sync_file = os.path.join(self.spool_dir, "node_synced")
        self.cache_clear_file = os.path.join(self.spool_dir, "cache_clear")
        self.node_joined_file = os.path.join(self.spool_dir, "new_node")
        self.realm_data_file_path = os.path.join(self.cache_dir, "realm-data.json")
        self.sync_status_file_path = os.path.join(self.cache_dir, "sync-status.json")

        self.controld_pidfile = os.path.join(self.pidfile_dir, "otpme-controld.pid")
        self.nsscache_pidfile = os.path.join(self.pidfile_dir, "nsscache-sync.pid")

        self.authd_socket_path = "socket://%s/otpme-authd" % self.sockets_dir
        self.hostd_socket_path = "socket://%s/otpme-hostd" % self.sockets_dir
        self.clusterd_socket_path = "socket://%s/otpme-clusterd" % self.sockets_dir

        # Directory to cache user logins (tokens) for offline usage.
        self.offline_dir = os.path.join(self.cache_dir, "offline")
        # Directory to store temporary files for login sessions.
        self.env_dir = os.path.join(self.cache_dir, "env")
        # Directory to cache nsscache(1) files.
        self.nsscache_dir = os.path.join(self.cache_dir, "nsscache")
        # Directory to cache user public keys (sign keys).
        self.sign_key_cache_dir = os.path.join(self.cache_dir, "signers")
        # Directory for SSH key deployment stuff.
        self.ssh_deploy_dir = os.path.join(self.cache_dir, "ssh")
        # Directory to cache SSH authorized_keys files.
        self.authorized_keys_dir = os.path.join(self.ssh_deploy_dir, "authorized_keys")
        # Directory to spool objects nsscache data.
        self.nsscache_spool_dir = os.path.join(self.spool_dir, "nsscache")
        # Directory to spool objects that needs to be updated in nsscache.
        self.nsscache_objects_dir = os.path.join(self.nsscache_spool_dir, "objects")
        # Last synced nsscache revision.
        self.nsscache_sync_file = os.path.join(self.nsscache_spool_dir, "synced_revision")
        # Directory to spool transaction.
        self.transaction_dir = os.path.join(self.spool_dir, "transactions")

        # Default key file.
        key_file = os.path.join(self.config_dir, "otpme.key")
        self.key_command = "file:/%s" % key_file

        # Load disk encryption module.
        try:
            self.disk_encryption_mod = get_module(self.disk_encryption)
        except Exception as e:
            msg = (_("Failed to load disk encryption module: %s") % e)
            raise OTPmeException(msg)

        # Set debug stuff.
        from otpme.lib import debug
        if self.debug_level("debug_timings") == 1:
            self.print_timing_warnings = True
        if self.debug_level("debug_timings") == 2:
            self.print_timing_results = True
        if self.debug_level("debug_timings") == 3:
            self.print_method_slowness = True

        if self.debug_level("debug_timings") > 0:
            debug.debug_timings = True
        if self.debug_level("method_calls") == 1:
            debug.trace_method_calls = True
        if self.debug_level("type_checking") == 1:
            debug.debug_type_checking = True

        if self.debug_level("method_calls") > 0 \
        or self.debug_level("debug_timings") > 0 \
        or self.debug_level("type_checking") > 0:
            os.environ['OTPME_DEBUG_NEED_DECORATOR'] = "True"

        # Get password from stdin.
        if self.read_stdin_pass and not self.stdin_pass:
            self.stdin_pass = sys.stdin.readline().replace("\n", "")

        # Get system user.
        system_user = self.system_user()

        # Make sure we create all paths before checking if logfile path is valid.
        if system_user == self.user or system_user == "root":
            # Make sure filesystem stuff is sane.
            self.create_paths()
            # Try to get master key.
            if not self.master_key:
                self.master_key = self.get_master_key()
            # Set current reload file modification time
            try:
                self.last_reload_file_mtime = os.path.getmtime(self.reload_file_path)
            except FileNotFoundError:
                self.last_reload_file_mtime = time.time()

        # Try to get password salt.
        if not self.password_hash_salt:
            self.password_hash_salt = self.get_password_salt()

        # Set logfile path if not already done.
        if (not self.use_syslog and not self.use_systemd_log and not self.log_file) or self.config_reload:
            if self.force_logfile:
                self.log_file = str(os.path.realpath(str(self.force_logfile)))
            else:
                if self.tool_name == "otpme-controld":
                    self.log_file = os.path.join(self.log_dir, "%s.log" % self.log_name.lower())
                else:
                    self.log_file = "/dev/null"

        if self.log_file and not self.use_syslog and not self.use_systemd_log:
            # Make sure logfile exists and has proper permissions.
            self.ensure_logfile(self.log_file)

        # Check if logger instance already exists.
        if configure_logger is None:
            if self.logger:
                configure_logger = False
            else:
                configure_logger = True

            # If this is a config reload we have to re-configure the logger.
            if self.config_reload:
                configure_logger = True

        # Create or reconfigure logger instance.
        if configure_logger:
            self.setup_logger(existing_logger=self.logger, pid=self.my_pid)

        if not self.config_reload and self.debug_enabled \
        and (not self.file_logging and not self.use_syslog \
        and not self.use_systemd_log):
            debug_levels_string = []
            for slot in sorted(self.debug_levels):
                level = self.debug_levels[slot]
                x = "%s:%s" % (slot, level)
                debug_levels_string.append(x)
            debug_levels_string = ", ".join(debug_levels_string)
            message(_("Tracebacks: %s") % self.print_tracebacks)
            message(_("Logging to file: %s") % self.file_logging)
            message(_("Debug Level: %s") % debug_levels_string)

        # Reset reload flags.
        self.config_reload = False
        self.user_config_reload = False

        if self.object_caches:
            for cache in self.object_caches:
                object_type = cache.split(":")[0]
                cache_size = cache.split(":")[1]
                self.cache_objects[object_type] = cache_size

        for x in self.default_listen_ports:
            x_port = self.default_listen_ports[x]
            x_socket = "0.0.0.0:%s" % x_port
            self.listen_sockets[x] = [x_socket]

    def find_conf_para_by_var(self, var_name):
        """ Find config parameter name by variable name. """
        for para_name in self.configfile_var_map:
            x_name = self.configfile_var_map[para_name]
            if var_name != x_name:
                continue
            return para_name

    def get_data_revision(self):
        from otpme.lib import backend
        result = backend.search(object_type="data_revision",
                                attribute="uuid",
                                value="*",
                                return_attributes=['data_revision'])
        if not result:
            return 1
        highest_revision = sorted(result)[-1]
        return highest_revision

    def update_data_revision(self):
        """ Update data revision timestamp. """
        from otpme.lib import backend
        from otpme.lib import locking
        from otpme.lib.classes.data_objects.data_revision import DataRevision
        if self.realm_init:
            return
        lock_id = "update_data_revision"
        lock = locking.acquire_lock(lock_type=self.DATA_REVISION_LOCK_TYPE,
                                                    lock_id=lock_id)
        try:
            result = backend.search(object_type="data_revision",
                                    attribute="uuid",
                                    value="*",
                                    return_type="instance")
            if not result:
                data_revision = DataRevision(realm=self.realm,
                                            site=self.site,
                                            data_revision=time.time())
                data_revision.add()
                return

            default_callback = self.get_callback()
            data_revision = result[0]
            data_revision.data_revision = time.time()
            data_revision._write(callback=default_callback)
        finally:
            lock.release_lock()

    def touch_node_sync_file(self, timestamp=None):
        from otpme.lib import locking
        from otpme.lib import filetools
        lock_id = "handle_node_sync_file"
        lock = locking.acquire_lock(lock_type=self.NODE_SYNC_LOCK_TYPE,
                                                    lock_id=lock_id)
        try:
            if timestamp is None:
                timestamp = time.time()
            x_file = self.node_sync_file
            if not os.path.exists(self.node_sync_file):
                x_file = "%s.tmp" % self.node_sync_file
                filetools.touch(x_file)
            os.utime(x_file, (timestamp, timestamp))
            if not os.path.exists(self.node_sync_file):
                os.rename(x_file, self.node_sync_file)
        finally:
            lock.release_lock()

    def remove_node_sync_file(self):
        from otpme.lib import locking
        from otpme.lib import filetools
        lock_id = "handle_node_sync_file"
        lock = locking.acquire_lock(lock_type=self.NODE_SYNC_LOCK_TYPE,
                                                    lock_id=lock_id)
        try:
            filetools.delete(self.node_sync_file)
        finally:
            lock.release_lock()

    def get_index_module(self):
        index_path = "otpme.lib.index.%s" % self.index_type
        index = importlib.import_module(index_path)
        return index

    def get_cache_module(self):
        cache_path = "otpme.lib.cache.%s" % self.cache_type
        _cache = importlib.import_module(cache_path)
        return _cache

    def get_cache_region(self, object_type):
        try:
            cache_region = self.cache_regions[object_type]
        except KeyError:
            msg = "No cache region registerd for object type: %s" % object_type
            raise OTPmeException(msg)
        return cache_region

    def debug_level(self, slot="base", new_level=None):
        """ Get/set debug level. """
        # Set new level.
        if new_level is None:
            # Get current level.
            try:
                level = self.debug_levels[slot]
            except:
                level = 0
            return level
        self.debug_levels[slot] = new_level

    def register_auth_on_action_hook(self, object_type, hook):
        try:
            hooks = self.auth_on_action_hooks[object_type]
        except:
            hooks = []
        if hook in hooks:
            return
        hooks.append(hook)
        self.auth_on_action_hooks[object_type] = hooks

    def register_method(self, name, method):
        """ Register method function. """
        if name in self.methods:
            msg = "Method already registered."
            raise AlreadyRegistered(msg)
        self.methods.append(name)
        return setattr(OTPmeConfig, name, method)

    def register_property(self, name, getx,
        setx=None, delx=None, doc="OTPmeconfig property."):
        """ Register property function. """
        if name in self.properties:
            msg = "Property already registered."
            raise AlreadyRegistered(msg)
        p = property(getx, setx, delx, doc)
        self.properties.append(name)
        return setattr(OTPmeConfig, name, p)

    def register_config_var(self, name, vtypes,
        default_value=None, config_file_parameter=None,
        user_config_file_parameter=None, force_main_config=False):
        """ Register config variable. """
        if hasattr(self, name):
            msg = "Config variable already registered: %s" % name
            raise AlreadyRegistered(msg)
        if not isinstance(vtypes, list):
            vtypes = [vtypes]
        self.config_var_types[name] = vtypes
        setattr(self, name, default_value)
        # Register config file parameter.
        if config_file_parameter:
            if config_file_parameter in self.configfile_var_map:
                msg = ("Config file parameter already registered: %s"
                        % config_file_parameter)
                raise AlreadyRegistered(msg)
            self.configfile_var_map[config_file_parameter] = name
        # Register user config file parameter.
        if user_config_file_parameter:
            if user_config_file_parameter in self.user_configfile_var_map:
                msg = ("User config file parameter already registered: %s"
                        % user_config_file_parameter)
                raise AlreadyRegistered(msg)
            self.user_configfile_var_map[user_config_file_parameter] = name
            self.user_configfile_params.append(user_config_file_parameter)
            # Check if this user config parameter should override a global
            # config file paremeter.
            override_global_config = False
            if not force_main_config:
                if user_config_file_parameter in self.configfile_var_map:
                    override_global_config = True
            if override_global_config:
                self.merge_user_configfile_params.append(user_config_file_parameter)

    def register_config_parameter(self, name, ctype,
        default_value=None, valid_values=None, object_types=[]):
        """ Register config parameter. """
        if name in self.valid_config_params:
            msg = "Config parameter already registered: %s" % name
            raise AlreadyRegistered(msg)
        self.valid_config_params[name] = {
                                            'type'          : ctype,
                                            'default'       : default_value,
                                            'valid_values'  : valid_values,
                                            'object_types'  : object_types,
                                        }

    def register_smartcard_type(self, smartcard_type, client_handler, server_handler):
        """ Register supported smartcard type. """
        if smartcard_type in self.supported_smartcards:
            msg = "Smartcard type already registered: %s" % smartcard_type
            raise AlreadyRegistered(msg)
        self.supported_smartcards[smartcard_type] = {}
        self.supported_smartcards[smartcard_type]['client_handler'] = client_handler
        self.supported_smartcards[smartcard_type]['server_handler'] = server_handler

    def get_smartcard_handler(self, smartcard_type):
        """ Get supported smartcard handlers. """
        try:
            client_handler = self.supported_smartcards[smartcard_type]['client_handler']
            server_handler = self.supported_smartcards[smartcard_type]['server_handler']
        except KeyError:
            msg = "Smartcard type not registered: %s" % smartcard_type
            raise NotRegistered(msg)
        return client_handler, server_handler

    def get_supported_smartcards(self):
        """ Get list with supported smartcard types. """
        return list(self.supported_smartcards)

    def get_ldap_settings(self, object_type):
        """ Return sub object types.. """
        try:
            ldap_settings = self.ldap_object_types[object_type]
        except:
            ldap_settings = {}
        return ldap_settings

    def get_sub_object_types(self, object_type):
        """ Return sub object types.. """
        try:
            sub_types = self.sub_object_types[object_type]
        except:
            sub_types = []
        return sub_types

    def register_object_type(self, object_type, tree_object=None,
        backend_object=True, uniq_name=False, object_cache=False,
        cache_region=None, add_before=[], add_after=[],
        sync_before=[], sync_after=[], backup_attributes=None):
        """ Register object type. """
        if tree_object:
            object_list = self.tree_object_types
        else:
            object_list = self.flat_object_types
        if object_type in object_list:
            msg = "Object type already registered: %s" % object_type
            raise AlreadyRegistered(msg)
        object_list.append(object_type)
        self.object_types = self.tree_object_types + self.flat_object_types
        if backup_attributes:
            self.backup_attributes[object_type] = backup_attributes
        if backend_object:
            if object_type not in self.backend_object_types:
                self.backend_object_types.append(object_type)
        if uniq_name:
            if object_type in self.name_uniq_objects:
                msg = "Object type already registered: %s" % object_type
                raise AlreadyRegistered(msg)
            self.name_uniq_objects.append(object_type)
        if object_type in self.cache_regions:
            msg = "Object type already registered: %s" % object_type
            raise AlreadyRegistered(msg)
        # Do not override config file cache settings.
        if object_type not in self.cache_objects:
            self.cache_objects[object_type] = object_cache
        self.cache_regions[object_type] = cache_region
        # Object add order.
        if object_type in self._object_add_order:
            msg = "Object type already registered: %s" % object_type
            raise AlreadyRegistered(msg)
        self._object_add_order[object_type] = {}
        self._object_add_order[object_type]['before'] = add_before
        self._object_add_order[object_type]['after'] = add_after
        self._object_sync_order[object_type] = {}
        self._object_sync_order[object_type]['before'] = sync_before
        self._object_sync_order[object_type]['after'] = sync_after

    def register_sub_object_type(self, object_type, stype):
        """ Register sub object type (e.g. token type). """
        try:
            sub_types = self.sub_object_types[object_type]
        except:
            sub_types = []
        if stype in sub_types:
            msg = ("Sub object type already registered: %s: %s"
                    % (object_type, stype))
            raise AlreadyRegistered(msg)
        sub_types.append(stype)
        self.sub_object_types[object_type] = sub_types

    def register_ldap_object(self, object_type,
        default_scope="one", scopes=['sub', 'one', 'base']):
        """ Register LDAP object type. """
        if object_type in self.ldap_object_types:
            msg = ("LDAP object type already registered: %s: %s"
                    % (object_type))
            raise AlreadyRegistered(msg)
        settings = {'default_scope':default_scope, 'scopes':scopes}
        self.ldap_object_types[object_type] = settings

    def get_backup_attributes(self, object_type):
        if object_type not in self.backup_attributes:
            msg = "Object type backup attributes not registered: %s" % object_type
            raise NotRegistered(msg)
        backup_attributes = list(self.backup_attributes[object_type])
        return backup_attributes

    def handle_post_object_registration(self):
        """
        Handle post object registration stuff. This method must be run
        AFTER all object have been registered! (e.g. in register module)
        """
        if "token" not in self.sub_object_types:
            return
        # Update valid values list with registered token types.
        self.valid_config_params['default_token_type']['valid_values'] = self.sub_object_types['token']

    def get_base_objects(self, object_type, early=False):
        """ Return sorted base objects. """
        try:
            x_objects = dict(self.base_objects[object_type])
        except:
            return {}
        x_sort = lambda x: x_objects[x]['pos']
        x_objects_sorted = sorted(x_objects, key=x_sort)
        ordered_dict = collections.OrderedDict()
        for x in x_objects_sorted:
            x_early = x_objects[x]['early']
            if x_early != early:
                continue
            ordered_dict[x] = dict(x_objects[x])
        return ordered_dict

    def register_base_object(self, object_type, name, stype=None,
        pos=None, template=False, call_methods=[], post_methods=[],
        post_register_method=None, attributes={}, early=False):
        """ Register base object. """
        try:
            x_objects = self.base_objects[object_type]
        except:
            x_objects = {}
        if name in x_objects:
            o_type = "%s%s" % (object_type[0].upper(), object_type[1:])
            msg = "%s already registered: %s" % (o_type, name)
            raise AlreadyRegistered(msg)
        if pos is None:
            pos = 0
            while True:
                found_collision = False
                for x in x_objects:
                    x_pos = x_objects[x]['pos']
                    if x_pos == pos:
                        found_collision = True
                        break
                if not found_collision:
                    break
                pos += 1
        x_objects[name] = {
                        'pos'                           : pos,
                        'type'                          : stype,
                        'early'                         : early,
                        'template'                      : template,
                        'attributes'                    : attributes,
                        'call_methods'                  : list(call_methods),
                        'post_methods'                  : list(post_methods),
                        }
        self.base_objects[object_type] = x_objects
        if post_register_method is not None:
            self._post_register_methods.append(post_register_method)

    def handle_post_base_object_registration(self):
        """
        Handle post object registration stuff. This method must be run
        AFTER all objects have been registered! (e.g. in register module)
        """
        for x_method in self._post_register_methods:
            x_method(self)

    def get_default_unit(self, object_type):
        """ Get default unit for object type. """
        try:
            default_unit = self.default_units[object_type]
        except:
            msg = "No default unit configured for object type: %s" % object_type
            raise OTPmeException(msg)
        return default_unit

    def register_default_unit(self, object_type, unit_path):
        """ Register default unit for object type. """
        if object_type in self.default_units:
            msg = ("Default unit for object type already registered: %s: %s"
                    % (object_type, unit_path))
            raise AlreadyRegistered(msg)
        self.default_units[object_type] = unit_path

    def get_internal_objects(self, object_type):
        """ Return sorted internal objects. """
        x_objects = dict(self.internal_objects[object_type])
        x_sort = lambda x: x_objects[x]['pos']
        x_objects_sorted = sorted(x_objects, key=x_sort)
        ordered_dict = collections.OrderedDict()
        for x in x_objects_sorted:
            ordered_dict[x] = dict(x_objects[x])
        return ordered_dict

    def register_internal_object(self, object_type, name, stype=None, pos=None):
        """ Register internal object. """
        try:
            x_objects = self.internal_objects[object_type]
        except:
            x_objects = {}
        if name in x_objects:
            o_type = "%s%s" % (object_type[0].upper(), object_type[1:])
            msg = "%s already registered: %s" % (o_type, name)
            raise AlreadyRegistered(msg)
        if pos is None:
            pos = 0
            while True:
                found_collision = False
                for x in x_objects:
                    x_pos = x_objects[x]['pos']
                    if x_pos == pos:
                        found_collision = True
                        break
                if not found_collision:
                    break
                pos += 1
        x_objects[name] = {
                        'pos'   : pos,
                        'type'  : stype,
                        }
        self.internal_objects[object_type] = x_objects

    def register_per_site_object(self, object_type, object_name):
        """ Register user that will exist per site. """
        try:
            per_site_objects = self.per_site_objects[object_type]
        except:
            per_site_objects = []
        if object_name in per_site_objects:
            msg = ("Per site %s already registered: %s"
                    % (object_type, object_name))
            raise AlreadyRegistered(msg)
        per_site_objects.append(object_name)
        self.per_site_objects[object_type] = per_site_objects

    def get_per_site_objects(self, object_type):
        """ Get per site objects. """
        try:
            per_site_objects = list(self.per_site_objects[object_type])
        except:
            per_site_objects = []
        return per_site_objects

    def register_object_template(self, object_type, object_name):
        """ Register object template. """
        try:
            current_template = self.object_templates[object_type]
        except KeyError:
            current_template = None
        if current_template == object_name:
            msg = "Object template already registered: %s" % object_name
            raise AlreadyRegistered(msg)
        self.object_templates[object_type] = object_name

    def get_object_template(self, object_type):
        """ Get object template. """
        try:
            object_template = self.object_templates[object_type]
        except KeyError:
            return
        return object_template

    def get_default_policies(self, object_type):
        """ Get default policies to be added to new objects. """
        try:
            default_policies = self.default_policies[object_type]
        except:
            default_policies = {}
        return default_policies

    def register_default_policy(self, object_type, policy_name, objects=[]):
        """ Register default policy to be added to new objects. """
        try:
            default_policies = self.default_policies[object_type]
        except:
            default_policies = {}
        try:
            policy_objects = default_policies[policy_name]
        except:
            policy_objects = []
        if policy_name in default_policies:
            msg = ("Default policy already registered: %s: %s"
                    % (object_type, policy_name))
            raise AlreadyRegistered(msg)
        for x in objects:
            if x in policy_objects:
                continue
            policy_objects.append(x)
        default_policies[policy_name] = policy_objects
        self.default_policies[object_type] = default_policies

    def register_dn_attribute(self, object_type, dn_attribute):
        """ Register DN attribute. """
        try:
            x_dn_attr = self.dn_attributes[object_type]
        except:
            x_dn_attr = None
        if x_dn_attr and x_dn_attr != dn_attribute:
            msg = ("DN attribute already registered: %s: %s"
                    % (object_type, x_dn_attr))
            raise AlreadyRegistered(msg)
        self.dn_attributes[object_type] = dn_attribute

    def get_default_extensions(self, object_type):
        """ Get default extensions to be added to new objects. """
        try:
            default_extensions = self.default_extensions[object_type]
        except:
            default_extensions = []
        return default_extensions

    def register_default_extension(self, object_type, extension_name):
        """ Register default extension to be added to new objects. """
        try:
            default_extensions = self.default_extensions[object_type]
        except:
            default_extensions = []
        if extension_name in default_extensions:
            msg = ("Default extension already registered: %s: %s"
                    % (object_type, extension_name))
            raise AlreadyRegistered(msg)
        default_extensions.append(extension_name)
        self.default_extensions[object_type] = default_extensions

    def register_extension(self, extension):
        """ Register OTPme extension. """
        if extension in self.extensions:
            msg = "Extension already registered: %s" % extension
            raise AlreadyRegistered(msg)
        self.extensions.append(extension)

    def get_ldif_attributes(self, extension, object_type):
        """ Get LDIF attributes of extension. """
        try:
            ext_attrs = list(self.attribute_types[extension][object_type])
        except:
            ext_attrs = []
        return ext_attrs

    def register_ldif_attribute(self, extension, object_type, attribute):
        """ Register LDIF attribute of extension. """
        try:
            self.attribute_types[extension]
        except:
            self.attribute_types[extension] = {}
        try:
            self.attribute_types[extension][object_type]
        except:
            self.attribute_types[extension][object_type] = []
        # Get already registered extension attributes.
        extension_attributes = self.attribute_types[extension][object_type]
        if attribute in extension_attributes:
            msg = ("LDIF attribute already registered: %s: %s"
                    % (extension, attribute))
            raise AlreadyRegistered(msg)
        extension_attributes.append(attribute)
        self.attribute_types[extension][object_type] = extension_attributes

    def register_index_attribute(self, attribute, ldif=False):
        """ Register attribute to be added to the search index. """
        if ldif:
            if attribute in self.ldap_index_attributes:
                msg = "LDIF index attribute already registered: %s" % attribute
                raise AlreadyRegistered(msg)
            self.ldap_index_attributes.append(attribute)
        else:
            if attribute in self.otpme_index_attributes:
                msg = "OTPme index attribute already registered: %s" % attribute
                raise AlreadyRegistered(msg)
            self.otpme_index_attributes.append(attribute)
        # Merged list of attributes that can be searched via the (file backend) index.
        self.index_attributes = self.otpme_base_attributes \
                            + self.otpme_index_attributes \
                            + ["ldif:%s" % i for i in self.ldap_index_attributes]

    def get_encryption_module(self, enc_type):
        """ Get encryption module. """
        if enc_type not in self.supported_encryption_types:
            msg = "Unsupported encryption type: %s" % enc_type
            raise UnsupportedEncryptionType(msg)
        enc_mod = self.supported_encryption_types[enc_type]['enc_mod']
        return enc_mod

    def register_encryption_type(self, enc_type, enc_mod, before=[], after=[]):
        """ Register hash type. """
        if enc_type in self.supported_encryption_types:
            msg = "Encryption type already registered: %s" % enc_type
            raise AlreadyRegistered(msg)
        self.supported_encryption_types[enc_type] = {}
        self.supported_encryption_types[enc_type]['after'] = after
        self.supported_encryption_types[enc_type]['before'] = before
        self.supported_encryption_types[enc_type]['enc_mod'] = enc_mod

    def get_encoding_module(self, enc_type):
        """ Get encoding module. """
        if enc_type not in self.supported_encoding_types:
            msg = "Unsupported encoding type: %s" % enc_type
            raise UnsupportedEncodingType(msg)
        enc_mod = self.supported_encoding_types[enc_type]
        return enc_mod

    def register_encoding_type(self, enc_type, enc_mod):
        """ Register encoding type. """
        if enc_type in self.supported_encoding_types:
            msg = "Encoding type already registered: %s" % enc_type
            raise AlreadyRegistered(msg)
        self.supported_encoding_types[enc_type] = enc_mod

    def get_compression_module(self, enc_type):
        """ Get compression module. """
        if enc_type not in self.supported_compression_types:
            msg = "Unsupported compression type: %s" % enc_type
            raise UnsupportedCompressionType(msg)
        enc_mod = self.supported_compression_types[enc_type]
        return enc_mod

    def register_compression_type(self, ctype, cmod):
        """ Register compression type. """
        if ctype in self.supported_compression_types:
            msg = "Compression type already registered: %s" % ctype
            raise AlreadyRegistered(msg)
        self.supported_compression_types[ctype] = cmod

    def get_ecdh_curves(self):
        """ Get supported ECDH curves ordered by strength. """
        from otpme.lib import stuff
        order_data = dict(self.supported_ecdh_curves)
        ecdh_curves = stuff.order_data_by_deps(order_data)
        return ecdh_curves

    def register_ecdh_curve(self, ecdh_curve, before=[], after=[]):
        """ Register ECDH curve. """
        if ecdh_curve in self.supported_ecdh_curves:
            msg = "ECDH curve already registered: %s" % hash_type
            raise AlreadyRegistered(msg)
        self.supported_ecdh_curves[ecdh_curve] = {}
        self.supported_ecdh_curves[ecdh_curve]['after'] = after
        self.supported_ecdh_curves[ecdh_curve]['before'] = before

    def get_hash_types(self):
        """ Get supported hash types ordered by strength. """
        from otpme.lib import stuff
        order_data = dict(self.supported_hash_types)
        hash_types_ordered = stuff.order_data_by_deps(order_data)
        return hash_types_ordered

    def get_hash_function(self, hash_type):
        """ Get hash function. """
        if hash_type not in self.supported_hash_types:
            msg = "Unsupported hash type: %s" % hash_type
            raise UnsupportedHashType(msg)
        hash_func = self.supported_hash_types[hash_type]['hash_function']
        return hash_func

    def get_hash_type_default_otps(self, hash_type):
        """ Get default options for hash type. """
        if hash_type not in self.supported_hash_types:
            msg = "Unsupported hash type: %s" % hash_type
            raise UnsupportedHashType(msg)
        default_opts = self.supported_hash_types[hash_type]['default_opts']
        return default_opts

    def get_hash_type_config_opts(self, hash_type):
        """ Get hash type config options. """
        if hash_type not in self.supported_hash_types:
            msg = "Unsupported hash type: %s" % hash_type
            raise UnsupportedHashType(msg)
        config_opts = self.supported_hash_types[hash_type]['config_opts']
        return config_opts

    def register_hash_type(self, hash_type, hash_func, default_opts=None,
        config_opts=None, before=[], after=[]):
        """ Register hash type. """
        if hash_type in self.supported_hash_types:
            msg = "Hash algorithm already registered: %s" % hash_type
            raise AlreadyRegistered(msg)
        self.supported_hash_types[hash_type] = {}
        self.supported_hash_types[hash_type]['after'] = after
        self.supported_hash_types[hash_type]['before'] = before
        self.supported_hash_types[hash_type]['hash_function'] = hash_func
        self.supported_hash_types[hash_type]['default_opts'] = default_opts
        self.supported_hash_types[hash_type]['config_opts'] = config_opts

    def get_otpme_daemons(self):
        """ Get OTPme daemons. """
        return list(self.daemons)

    def register_otpme_daemon(self, daemon):
        """ Register OTPme daemon. """
        if daemon in self.daemons:
            msg = "Daemon already registered: %s" % daemon
            raise AlreadyRegistered(msg)
        self.daemons.append(daemon)

    def get_otpme_protocols(self, daemon, server=False):
        """ Get supported OTPme protocols. """
        if server:
            ptype = "server"
        else:
            ptype = "client"
        try:
            daemon_protos = self.supported_protocols[daemon][ptype]
        except:
            daemon_protos = []
        return daemon_protos

    def register_otpme_protocol(self, daemon, protocol, server=False):
        """ Register supported OTPme protocol. """
        if server:
            ptype = "server"
        else:
            ptype = "client"
        try:
            daemon_protos = self.supported_protocols[daemon][ptype]
        except:
            daemon_protos = []
        if protocol in daemon_protos:
            msg = "Protocol already registered: %s" % protocol
            raise AlreadyRegistered(msg)
        daemon_protos.append(protocol)
        if not daemon in self.supported_protocols:
            self.supported_protocols[daemon] = {}
        self.supported_protocols[daemon][ptype] = daemon_protos

    def get_sync_object_types(self, host_type):
        """ Get object types to sync. """
        try:
            sync_object_types = copy.deepcopy(self.sync_object_types[host_type])
        except:
            msg = "Host type not registered for sync: %s" % host_type
            raise NotRegistered(msg)
        return sync_object_types

    def register_object_sync(self, host_type, object_type):
        """ Register object type to be synced between hosts/nodes. """
        try:
            sync_object_types = self.sync_object_types[host_type]
        except:
            sync_object_types = []
        if object_type in sync_object_types:
            msg = "Object type already registered for sync: %s" % object_type
            raise AlreadyRegistered(msg)
        sync_object_types.append(object_type)
        self.sync_object_types[host_type] = sync_object_types

    def get_cluster_object_types(self):
        """ Get object types to cluster. """
        cluster_object_types = copy.deepcopy(self.cluster_object_types)
        return cluster_object_types

    def register_cluster_sync(self, object_type):
        """ Register object type to be clustered between nodes. """
        if object_type in self.cluster_object_types:
            msg = "Object type already registered for clustering: %s" % object_type
            raise AlreadyRegistered(msg)
        self.cluster_object_types.append(object_type)

    def raise_exception(self, message=None):
        """ Raise exceptions if requested (-dd) and print info. """
        if not self.raise_exceptions:
            return
        #import inspect
        #for i in range(0, len(inspect.stack())):
        #    print(inspect.stack()[i][3])
        msg = (_("WARNING!!!!! Raising exceptions is enabled (-dee). "
            "This exception would not occur in normal operation mode!"))
        error_message(msg)
        now = datetime.datetime.now()
        now = now.strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]
        msg = "Exception time: %s" % now
        error_message(msg)
        msg = "Exception PID: %s" % os.getpid()
        error_message(msg)
        msg = "Exception daemon: %s" % self.daemon_name
        error_message(msg)
        if message is not None:
            error_message(message)
        #from otpme.lib import debug
        #debug.trace()

        #import traceback, sys
        #exc_type, exc_value, exc_traceback = sys.exc_info()
        #traceback.print_tb(exc_traceback, limit=1, file=sys.stdout)
        try:
            raise
        except RuntimeError:
            pass

    def get_callback(self):
        """ Get default callback. """
        from otpme.lib.job.callback import JobCallback
        # The default callback is used in many classes as default and will be set
        # to a "real" callback that can be used to send messages etc. to the user.
        # For example when the User().delete() method is called from within the
        # management daemon a JobCallback() is passed to it that can ask the user
        # for confirmation, return the deletion status etc. But the default
        # callback is not intended to do such things. It is intended to be used as
        # a replacement for "return" and "raise Exception()" when the same method
        # is used non-interactive (as API). This way we can prevent many if:else
        # statments e.g. to check if we have to return a "Cannot delete User."
        # message when called from an interactive session or raise an exception when
        # called as API.
        default_callback = JobCallback(name="default_callback")
        return default_callback

    def system_user(self):
        """ get current system user we run as. """
        from otpme.lib import stuff
        pid = os.getpid()
        return stuff.get_pid_user(pid)

    def system_group(self):
        """ Get current system group we run as. """
        from otpme.lib import stuff
        pid = os.getpid()
        pid_group = stuff.get_pid_group(pid)
        return pid_group

    @property
    def login_user(self):
        if self._login_user:
            return self._login_user
        # Get login user from agent.
        self._login_user = self.get_login_user()
        return self._login_user

    @login_user.setter
    def login_user(self, login_user):
        self._login_user = login_user

    def get_login_user(self):
        """ Get login user. """
        from otpme.lib import stuff
        # Else use already logged in user from agent.
        try:
            agent_user = stuff.get_agent_user()
        except:
            agent_user = None
        return agent_user

    def get_user_locks_dir(self, username):
        user_locks_dir = "%s/otpme-%s/locks/" % (self.tmp_dir, username)
        return user_locks_dir

    def get_user_signers_dir(self, username):
        user_config_dir = self.get_user_conf_dir(username)
        user_signers_dir = "%s/signers/" % user_config_dir
        return user_signers_dir

    def get_user_conf_dir(self, username=None):
        """ Get path to users config dir. """
        # Get users home dir path
        if username:
            user_home = os.path.expanduser("~%s" % username)
        else:
            user_home = os.path.expanduser("~")
        # Users OTPme config dir
        conf_dir = "%s/.otpme" % user_home
        return conf_dir

    def get_user_conf_file(self, username=None):
        """ Get path to users OTPme config file. """
        conf_dir = self.get_user_conf_dir(username)
        conf_file = os.path.join(conf_dir, "otpme.conf")
        return conf_file

    def get_user_env_dir(self, username=None):
        """ Get path to otpme-pinentry autoconfirm file. """
        if username is None:
            username = self.login_user
        user_env_dir = "%s/%s" % (self.env_dir, username)
        return user_env_dir

    def get_pinentry_message_file(self, username=None):
        """ Get path to otpme-pinentry message file. """
        if username is None:
            username = self.login_user
        user_env_dir = self.get_user_env_dir(username)
        message_file = "%s/.pinentry_messages" % user_env_dir
        return message_file

    def get_pinentry_autoconfirm_file(self, username=None):
        """ Get path to otpme-pinentry autoconfirm file. """
        if username is None:
            username = self.login_user
        user_env_dir = self.get_user_env_dir(username)
        autoconfirm_file = "%s/.pinentry_autoconfirm" % user_env_dir
        return autoconfirm_file

    def ensure_user_conf_file(self, username=None):
        """ Create OTPme config file in users home directory. """
        from otpme.lib import filetools
        if not username:
            username = self.system_user()
        conf_dir = self.get_user_conf_dir(username)
        conf_file = self.get_user_conf_file(username)
        _signers_dir = os.path.join(conf_dir, "signers")
        if not os.path.exists(conf_dir):
            self.logger.debug("Creating directory: %s" % conf_dir)
            os.mkdir(conf_dir)
        if not os.path.exists(conf_file):
            self.logger.debug("Creating config file: %s" % conf_file)
            fd = open(conf_file, "w")
            fd.write('#AUTO_SIGN="True"\n')
            fd.close()
        if not os.path.exists(_signers_dir):
            self.logger.debug("Creating directory: %s" % _signers_dir)
            os.mkdir(_signers_dir)
        directories = {
                conf_dir : 0o700,
                _signers_dir : 0o700,
                }
        files = {
                conf_file : 0o600,
                }
        filetools.ensure_fs_permissions(directories=directories,
                                        files=files,
                                        user=username, group=True)

    def read_user_conf_file(self, user_conf_file, quiet=False):
        """ Read user config file. """
        from otpme.lib import stuff

        if not os.path.exists(user_conf_file):
            return {}

        try:
            # Open config file for reading.
            fd = open(user_conf_file, 'r')
        except (OSError, IOError) as error:
            raise Exception(_("Error reading config file: %s") % error)

        # Read complete file.
        file_content = fd.read()
        fd.close()

        # Verify config file checksum.
        config_file_md5 = stuff.gen_md5(file_content)
        if config_file_md5 == self.last_user_config_file_checksum:
            return self.user_config

        if not quiet:
            if self.user_config_reload:
                msg = ("Reloading config file '%s'." % user_conf_file)
            else:
                msg = ("Loading config file: %s" % user_conf_file)
            if self.logger:
                self.logger.debug(msg)
            else:
                message(msg)

        self.last_user_config_file_checksum = config_file_md5

        self.user_config = stuff.conf_to_dict(file_content)
        # Make user config includes only allowed parameters.
        for x in dict(self.user_config):
            if x in self.user_configfile_params:
                continue
            msg = (_("Unknown config file parameter: %s: %s")
                    % (user_conf_file, x))
            error_message(msg)
            self.user_config.pop(x)
        return self.user_config

    def create_paths(self):
        """
        Make sure needed directories and files
        exists with the correct permissions.
        """
        # FIXME: add register_path!
        from otpme.lib import filetools
        files = {
                    self.uuid_file : 0o664,
                    }

        files_create = {
                    self.reload_file_path       : 0o664,
                    self.realm_data_file_path   : 0o664,
                    self.sync_status_file_path  : 0o664,
                    }

        directories = {
                    # Data dir contains OTPme data (e.g. index).
                    self.data_dir : 0o770,
                    # Spool dir contains hashes of used/failed passwords etc.
                    # and should not be world readable.
                    self.spool_dir : 0o770,
                    # Directory to store objects while synchronizing.
                    self.sync_dir : 0o770,
                    # Run dir contains e.g. agent sockets and thus
                    # needs to be world readable.
                    self.run_dir : 0o775,
                    # Contains log files
                    self.log_dir : 0o750,
                    self.cache_dir : 0o775,
                    # We write offline tokens to offline dir and thus we need
                    # it world writeable.
                    self.offline_dir : 0o1777,
                    self.nsscache_dir : 0o775,
                    self.ssh_deploy_dir : 0o750,
                    self.sign_key_cache_dir : 0o775,
                    self.nsscache_spool_dir : 0o770,
                    self.nsscache_objects_dir : 0o770,
                    self.authorized_keys_dir : 0o750,
                    self.transaction_dir : 0o770,
                    # pam_otpme creates softlinks to users ssh/gpg-agent sockets
                    # e.g. on screen unlock which runs with user permissions.
                    self.env_dir : 0o1777,
                    # otpme-agent runs with user permissions and writes its pidfile
                    # and sockets to the dirs below.
                    self.pidfile_dir : 0o1777,
                    self.sockets_dir : 0o1777,
                    self.locks_dir : 0o1777,
                    # Directory with signers (users) public keys must be world
                    # readable.
                    self.signers_dir : 0o755,
                    }

        if self.key_command.startswith("file://"):
            key_file = re.sub('^file:/', '', self.key_command)
            files[key_file] = 0o600

        if self.handle_files_dirs:
            # Ensure dirs/files.
            filetools.ensure_fs_permissions(directories=directories,
                                            files=files,
                                            files_create=files_create,
                                            user=self.user,
                                            group=self.group)
        else:
            for x in directories:
                if os.path.exists(x):
                    continue
                msg = ("No such file or directory: %s" % x)
                raise OTPmeException(msg)

    def ensure_logfile(self, logfile):
        """ Make sure we have a logfile we can write to. """
        from otpme.lib import filetools
        # Check if path to logfile exists and is writable
        logfile_parent_dir = os.path.dirname(logfile)
        if not os.path.exists(logfile):
            if not os.path.exists(logfile_parent_dir):
                raise Exception(_("No such file or directory: %s")
                                % logfile_parent_dir)
            if not os.access(logfile_parent_dir, os.W_OK):
                raise Exception(_("Permission denied: %s") % logfile_parent_dir)
            # Make sure logfile exists
            filetools.create_file(path=logfile,
                                    content="",
                                    user=self.user,
                                    group=self.group,
                                    mode=0o660)

        if not os.access(logfile, os.W_OK):
            raise Exception(_("Permission denied: %s") % logfile)

    def gen_master_key(self, master_pass_salt=None, master_pass=None,
        skip_if_exists=False, force=False):
        """ Generate AES master key from passphrase. """
        if not self.key_command.startswith("file://"):
            msg = (_("KEY_COMMAND is not set to a file. "
                    "Unable to generate AES key."))
            raise OTPmeException(msg)
        from otpme.lib import cli
        from otpme.lib import filetools

        key_file = re.sub('^file:/', '', self.key_command)
        if os.path.exists(key_file):
            if skip_if_exists:
                return
            if not force:
                msg = (_("Warning: Key file '%s' exists. Overwrite?: ") % key_file)
                ask = cli.user_input(msg)
                if str(ask).lower() != "y":
                    return

        message("Generating encrytion master key...")
        if not master_pass:
            if master_pass_salt:
                prompt = "Please give master password: "
                master_pass = cli.read_pass(prompt=prompt)
            else:
                while True:
                    prompt = "Please give new master password: "
                    master_pass1 = cli.read_pass(prompt=prompt)
                    prompt = "Please repeat master password: "
                    master_pass2 = cli.read_pass(prompt=prompt)
                    if master_pass1 != master_pass2:
                        msg = "Passwords do not match. Please try again."
                        error_message(msg)
                    else:
                        master_pass = master_pass1
                        break
        # Get master key and salt.
        x = self.disk_encryption_mod.derive_key(secret=master_pass,
                                        salt=master_pass_salt,
                                        hash_type=self.master_key_hash_type)
        self.master_key = x['key']
        master_pass_salt = x['salt']

        # Write master key to file.
        try:
            filetools.create_file(path=key_file,
                                content=self.master_key,
                                user=self.user,
                                group=self.group,
                                mode=0o600)
        except Exception as e:
            msg = (_("Error writing master key file: %s") % e)
            raise OTPmeException(msg)
        # Write master key salt to file.
        try:
            filetools.create_file(path=self.master_pass_salt_file,
                                    content=master_pass_salt,
                                    user=self.user,
                                    group=self.group,
                                    mode=0o600)
        except Exception as e:
            msg = (_("Error writing master key salt file: %s") % e)
            raise OTPmeException(msg)

    def get_master_key(self):
        """ Get master key from file or script output. """
        master_key = None
        if self.key_command.startswith("file://"):
            key_file = re.sub('^file:/', '', self.key_command)
            if os.path.exists(key_file):
                fd = open(key_file, "r")
                master_key = fd.read().replace("\n", "")
                fd.close()
        else:
            # Try to get master key via script.
            from subprocess import PIPE
            from subprocess import Popen
            #pipe = Popen(self.key_command, stdout=PIPE, stderr=PIPE, shell=True)
            pipe = Popen(self.key_command, stdout=PIPE, stderr=PIPE, shell=False)
            # Get script stdout and stderr.
            script_stdout, script_stderr = pipe.communicate()
            # Get script exit code.
            script_returncode = pipe.returncode
            if script_returncode != 0:
                msg = (_("Error running KEY_COMMAND: %s") % script_stderr)
                raise OTPmeException(msg)
            master_key = script_stdout.replace("\n", "")
        return master_key

    def set_password_salt(self, salt=None):
        """ Set/Generate salt used when hashing passwords. """
        from otpme.lib import stuff
        from otpme.lib import filetools
        if not salt:
            if os.path.exists(self.password_hash_salt_file):
                return
            # Generate realm uniq password hash salt.
            message("Generating password salt...")
            salt = stuff.gen_secret(32)
        # Write master salt to file.
        try:
            filetools.create_file(path=self.password_hash_salt_file,
                                    content=salt,
                                    user=self.user,
                                    group=self.group,
                                    mode=0o644)
        except Exception as e:
            msg = (_("Error writing salt file: %s") % e)
            raise OTPmeException(msg)

    def get_password_salt(self):
        """ Get password salt from file. """
        salt = None
        if os.path.exists(self.password_hash_salt_file):
            fd = open(self.password_hash_salt_file, "r")
            salt = fd.read().replace("\n", "")
            fd.close()
        return salt

    def get_agent_socket(self, user=None):
        """ Get path to agent socket. """
        if user:
            agent_user = user
        else:
            agent_user = self.system_user()
        socket_uri = "socket://%s/otpme-agent-%s" % (self.sockets_dir, agent_user)
        return socket_uri

    def get_agent_pidfile(self, user=None):
        """ Get path to agent pidfile. """
        if user:
            agent_user = user
        else:
            agent_user = self.system_user()
        pidfile_name = "otpme-agent-%s.pid" % agent_user
        pidfile = os.path.join(self.pidfile_dir, pidfile_name)
        return pidfile

    def check_config_reload(self):
        """ Check if config reload is needed. """
        # Calculate time since last config file read.
        config_age = int(time.time() - self.last_config_reload_check)

        # Check if config age is greater than configured interval.
        if config_age > self.reload_config_interval:
            # Get current config file modification time.
            try:
                config_file_mtime = os.path.getmtime(self.config_file)
            except FileNotFoundError:
                config_file_mtime = time.time()

            # Get current reload file modification time.
            try:
                reload_file_mtime = os.path.getmtime(self.reload_file_path)
            except FileNotFoundError:
                reload_file_mtime = time.time()

            # If current config file modification time differs from timstamp saved
            # in config module a reload is needed.
            if config_file_mtime != self.last_config_file_mtime:
                return True, "Config file has new modification time. Reload needed..."
            elif reload_file_mtime != self.last_reload_file_mtime:
                self.last_reload_file_mtime = reload_file_mtime
                return True, "Got reload command via reload file."
            else:
                # Remember when we have check if a config reload is needed.
                self.last_config_reload_check = time.time()
                return False, ""
        else:
            return False, ""

    def check_modules(self):
        """ Check if all required modules are installed. """
        try:
            import colorlog
        except Exception as e:
            msg = (_("Failed to load module 'colorlog': %s") % e)
            raise Exception(msg)
        del(colorlog)

    def verify(self):
        """ Check OTPme config. """
        # check if pwgen is executable
        if not os.access(self.pwgen_bin, os.X_OK):
            msg = ("Cannot execute pwgen. Please check your config.")
            raise OTPmeException(msg)

        if not isinstance(self.logout_pass_len, int) or self.logout_pass_len < 1:
            msg = ("LOGOUT_PASS_LEN must be greater than 0. Please "
                    "check your config.")
            raise OTPmeException(msg)

        if not isinstance(self.reload_config_interval, int) or self.reload_config_interval < 1:
            msg = ("RELOAD_CONFIG_INTERVAL must be greater than 0. "
                    "Please check your config.")
            raise OTPmeException(msg)

        for x in self.object_types:
            if x in self.cache_objects:
                continue
            msg = "Missing cache size for object type: %s" % x
            raise OTPmeException(msg)

        return True

    def read(self, quiet=False):
        """ Read config file. """
        from otpme.lib import stuff
        if not os.path.exists(self.config_file):
            error_message(_("Missing config file: %s") % self.config_file)
            sys.exit(1)
        try:
            # Open config file for reading.
            fd = open(self.config_file, 'r')
        except (OSError, IOError) as error:
            raise Exception(_("Error reading config file: %s") % error)

        if not quiet:
            if self.config_reload:
                msg = ("Reloading config file '%s'." % self.config_file)
            else:
                msg = ("Loading config file '%s'." % self.config_file)
            if self.logger:
                self.logger.debug(msg)
            else:
                message(msg)

        # Read complete file.
        file_content = fd.read()
        fd.close()

        # Verify config file checksum.
        config_file_md5 = stuff.gen_md5(file_content)
        if config_file_md5 == self.last_config_file_checksum:
            return self.main_config

        self.last_config_file_checksum = str(config_file_md5)

        # Convert config file content to object config (dict).
        main_config = stuff.conf_to_dict(file_content)

        # Timestamp of the last reload check.
        self.last_config_reload_check = time.time()
        # Remember config file mtime from last read.
        try:
            self.last_config_file_mtime =  os.path.getmtime(self.config_file)
        except FileNotFoundError:
            self.last_config_file_mtime = time.time()
        return main_config

    def set_realm(self, name, uuid):
        """ Set our realm. """
        self.realm = name
        self.realm_uuid = uuid

    def set_site(self, name, uuid, address, auth_fqdn=None, mgmt_fqdn=None):
        """ Set our site. """
        self.site = name
        self.site_uuid = uuid
        self.site_address = address
        self.site_auth_fqdn = auth_fqdn
        self.site_mgmt_fqdn = mgmt_fqdn

    @property
    def node_vote(self):
        from otpme.lib import multiprocessing
        try:
            node_vote = multiprocessing.get_dict(name="node_vote")['node_vote']
        except KeyError:
            node_vote = 0
        return node_vote

    @node_vote.setter
    def node_vote(self, new_vote):
        from otpme.lib import multiprocessing
        multiprocessing.get_dict(name="node_vote")['node_vote'] = new_vote

    def get_master_node(self):
        from otpme.lib import multiprocessing
        try:
            master_node = multiprocessing.get_dict(name="master_node")['master']
        except KeyError:
            master_node = None
        return master_node

    @property
    def master_node(self):
        master_node = self.get_master_node()
        if not master_node:
            return False
        try:
            this_node = self.host_data['name']
        except:
            return False
        if this_node == master_node:
            return True
        return False

    @property
    def realm_master(self):
        from otpme.lib import backend
        from otpme.lib.classes.realm import Realm
        # Check if realm exists, set realm and realm master.
        _realm = Realm(name=self.realm)
        if not _realm.exists():
            msg = (_("Unknown realm: %s") % self.realm)
            raise OTPmeException(msg)
        realm_master = backend.get_object(object_type="site",
                                        uuid=_realm.master)
        if not realm_master:
            return
        return realm_master.name

    @property
    def realm_master_uuid(self):
        from otpme.lib import backend
        # Check if realm exists, set realm and realm master.
        result = backend.search(object_type="realm",
                                attribute="name",
                                value=self.realm,
                                return_type="instance")
        if not result:
            return
        _realm = result[0]
        # FIXME: This is a test to find a long standing bug where _realm is a node object on sites sync.
        try:
            _realm.master
        except:
            print("realm object", _realm)
            print("realm", self.realm)
        realm_master = backend.get_object(object_type="site",
                                        uuid=_realm.master)
        if not realm_master:
            return
        return realm_master.uuid

    @property
    def realm_master_address(self):
        from otpme.lib import backend
        from otpme.lib.classes.realm import Realm
        # Check if realm exists, set realm and realm master.
        _realm = Realm(name=self.realm)
        if not _realm.exists():
            msg = (_("Unknown realm: %s") % self.realm)
            raise OTPmeException(msg)
        realm_master = backend.get_object(object_type="site",
                                        uuid=_realm.master)
        if not realm_master:
            return
        return realm_master.address

    @property
    def realm_master_node(self):
        if not self.uuid:
            return
        if not self.site_uuid:
            return
        if not self.realm_master_uuid:
            return
        if self.site_uuid == self.realm_master_uuid:
            if self.master_node:
                return True
        return False

    @property
    def realm_ca_path(self):
        # Set realm CA path.
        if not self.realm or not self.site:
            return
        cas_unit = self.get_default_unit("ca")
        realm_ca_path = os.path.join("/",
                                    self.realm,
                                    self.site,
                                    cas_unit,
                                    self.realm_ca)
        return realm_ca_path

    @property
    def site_ca_path(self):
        # Set realm CA path.
        if not self.realm or not self.site:
            return
        cas_unit = self.get_default_unit("ca")
        realm_ca_path = os.path.join("/",
                                    self.realm,
                                    self.site,
                                    cas_unit,
                                    self.site_ca)
        return realm_ca_path

    @property
    def logger(self):
        if not self._logger:
            self.setup_logger()
        return self._logger

    def setup_logger(self, banner=None, existing_logger=None,
        log_file=False, logger_syslog=False, logger_systemd=False,
        timestamps=None, pid=None, logger_color_logs=None, **kwargs):
        """ Configure logger. """
        logger_logfile = log_file
        logger_loglevel = self.loglevel
        if logger_color_logs is None:
            logger_color_logs = self.color_logs

        # By default we want get_logger() to use the log name as banner.
        if banner is None:
            banner = True

        # Set timestamps to True if it was not explicitly set and debug timestamps
        # are enabled.
        if timestamps is None:
            if self.debug_level("debug_timestamps") > 0:
                timestamps = True

        if self.debug_enabled:
            # If debug is enabled (-d) force loglevel to "DEBUG".
            logger_loglevel = "DEBUG"
            # Check if we should log to file or use syslog. If none is set log
            # messages are printed to stdout.
            if self.file_logging and not logger_logfile:
                logger_logfile = self.log_file
            elif self.use_syslog:
                logger_syslog = True
            elif self.use_systemd_log:
                logger_systemd = True
            elif self.tool_name == "pam_otpme":
                if self.pam_use_logfile:
                    logger_logfile = self.pam_logfile
                elif self.pam_use_syslog:
                    logger_syslog = True
                elif self.pam_use_systemd:
                    logger_systemd = True
        else:
            if self.file_logging and not logger_logfile:
                logger_logfile = self.log_file
            elif self.use_syslog:
                logger_syslog = True
            elif self.use_systemd_log:
                logger_systemd = True
            elif self.tool_name == "pam_otpme":
                if self.pam_use_logfile:
                    logger_logfile = self.pam_logfile
                elif self.pam_use_syslog:
                    logger_syslog = True
                elif self.pam_use_systemd:
                    logger_systemd = True
            elif self.tool_name == "radius_module":
                logger_logfile = self.radius_mod_logfile
                if timestamps is None:
                    timestamps = True
            elif self.tool_name == "otpme-mount":
                #logger_syslog = True
                logger_systemd = True
                #logger_logfile = "/tmp/mount.log"
            elif not self.file_logging:
                # If we are not in debug mode and logging is not enabled throw away
                # log messages.
                logger_logfile = "/dev/null"

        self._logger = log.get_logger(log_name=self.log_name, pid=pid, banner=banner,
                                logfile=logger_logfile, syslog=logger_syslog,
                                systemd=logger_systemd, level=logger_loglevel,
                                color_logs=logger_color_logs, timestamps=timestamps,
                                logger=existing_logger, **kwargs)
        return self.logger

    def get_extensions(self):
        """ Return list with all installed OTPme extensions. """
        extensions = []
        for i in os.listdir(self.extensions_dir):
            ext_dir = os.path.join(self.extensions_dir, i)
            ext_file = os.path.join(ext_dir, "%s.py" % i)
            if os.path.isfile(ext_file):
                extensions.append(i)
        return extensions

    def get_realm_data(self):
        """ Get realm data from cache file. """
        import json
        from otpme.lib import filetools
        try:
            realm_data = filetools.read_file(path=self.realm_data_file_path)
        except Exception as e:
            msg = (_("Unable to read realm data file: %s") % e)
            raise OTPmeException(msg)
        try:
            realm_data = json.loads(realm_data)
        except Exception as e:
            msg = "Failed to decode realm data: %s" % e
            raise OTPmeException(msg)
        return realm_data

    def update_realm_data(self):
        """ Update realm data cache file. """
        import json
        from otpme.lib import filetools
        realm_data = {
                    'realm'         : self.realm,
                    'realm_uuid'    : self.realm_uuid,
                    'site'          : self.site,
                    'site_uuid'     : self.site_uuid,
                    'site_address'  : self.site_address,
                    'site_auth_fqdn': self.site_auth_fqdn,
                    'site_mgmt_fqdn': self.site_mgmt_fqdn,
                    }
        realm_data = json.dumps(realm_data, sort_keys=True, indent=4)
        try:
            filetools.create_file(path=self.realm_data_file_path,
                                content=realm_data,
                                user=self.user,
                                group=self.group,
                                mode=0o664)
        except Exception as e:
            msg = (_("Unable to save realm data: %s") % e)
            raise OTPmeException(msg)


    def get_sync_status(self, realm, site, sync_type):
        """ Get sync status of this host/node. """
        try:
            x_status = self.sync_status[realm][site][sync_type]['status']
        except:
            x_status = "unknown"
        return x_status

    def update_sync_status(self, realm, site, status, sync_type, progress=0):
        """ Update sync status. """
        import json
        from otpme.lib import locking
        from otpme.lib import filetools
        # Check for valid status.
        if status is True or status is None:
            status = "success"
        if status is False:
            status = "failed"
        valid_status = ['success', 'failed', 'running', 'disabled']
        if status not in valid_status:
            msg = (_("Invalid status: %s [%s]")
                % (status, ",".join(valid_status)))
            raise OTPmeException(msg)
        # Make sure shared sync status dict is up-to-date.
        try:
            x = dict(self.sync_status[realm])
        except:
            x = {}
        if not site in x:
            x[site] = {}
        if not sync_type in x[site]:
            x[site][sync_type] = {}
        # Get sync type from shared dict.
        x[site][sync_type]['status'] = status
        if status == "success":
            x[site][sync_type]['last_run'] = time.time()
        if status == "running":
            if progress == 0:
                # Set sync start time.
                x[site][sync_type]['last_run'] = time.time()
            x[site][sync_type]['progress'] = progress
        if status == "failed":
            x[site][sync_type]["last_failed"] = time.time()

        # Update sync status.
        self.sync_status[realm] = x

        # Update status file.
        if status in ['success', 'failed', 'disabled']:
            # Get lock.
            lock_id = "update_sync_status"
            lock = locking.acquire_lock(lock_type=self.SYNC_STATUS_LOCK_TYPE,
                                                        lock_id=lock_id)
            status_json_string = self.sync_status.copy()
            status_json_string = json.dumps(status_json_string,
                                            sort_keys=True,
                                            indent=4)
            try:
                filetools.create_file(path=self.sync_status_file_path,
                                    content=status_json_string,
                                    user=self.user,
                                    group=self.group,
                                    mode=0o660)
            except Exception as e:
                msg = (_("Unable to save sync status: %s") % e)
                raise OTPmeException(msg)
            finally:
                lock.release_lock()

    def load_sync_status(self):
        """ Load sync status from file. """
        import json
        from otpme.lib import locking
        from otpme.lib import filetools
        lock_id = "update_sync_status"
        lock = locking.acquire_lock(lock_type=self.SYNC_STATUS_LOCK_TYPE,
                                lock_id=lock_id, write=False)
        try:
            status_json_string = filetools.read_file(self.sync_status_file_path)
        except Exception as e:
            msg = (_("Unable to load sync status: %s") % e)
            raise OTPmeException(msg)
        finally:
            lock.release_lock()
        if not status_json_string:
            return
        try:
            x_status = json.loads(status_json_string)
        except Exception as e:
            msg = (_("Unable to decode sync status: %s") % e)
            raise OTPmeException(msg)
        for realm in x_status:
            x = x_status[realm]
            self.sync_status[realm] = x
