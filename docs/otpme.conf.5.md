# OTPME.CONF(5)

## NAME

otpme.conf - OTPme configuration file

## SYNOPSIS

*/etc/otpme/otpme.conf*

## DESCRIPTION

The
**otpme.conf**
file configures the OTPme authentication system. It uses a simple KEY="VALUE" format. Lines starting with # are comments.

A distribution template is provided at
/etc/otpme/otpme.conf.dist.

## GENERAL

**BIN_DIR**
:   Path to OTPme command binaries.

**TIMEZONE**
:   Timezone used for certificates etc. (e.g. "Europe/Berlin").

**LANGUAGE**
:   Language for OTPme output (e.g. "en").

**LOG_LANGUAGE**
:   Language for log messages.

**USER**
:   System user OTPme runs as (default: "otpme").

**GROUP**
:   System group OTPme runs as (default: "otpme").

**HANDLE_FILES_DIRS**
:   If True, OTPme creates missing directories/files and sets permissions automatically.

**PINENTRY**
:   Pinentry program to use (default: "/usr/bin/pinentry").

**PWGEN**
:   Path to pwgen binary for password generation.

**USE_MGMTD_SOCKET**
:   Enable use of mgmtd socket (--socket) by default. Makes sense on nodes only.

## INDEX DATABASE

**INDEX**
:   Index database type: "sqlite3", "postgres" or "mysql". Run "otpme-tool index stop" before changing this.

**AUTOSTART_INDEX**
:   Autostart index database on daemon start.

### SQLite3

**SQLITE3_BIN**
:   Path to sqlite3 binary.

**SQLITE3_PRAGMA_SYNCHRONOUS**
:   SQLite3 synchronous pragma setting (default: "NORMAL").

### PostgreSQL

**POSTGRES_PG_CTL_BIN**
:   Path to pg_ctl binary.

**POSTGRES_PSQL_BIN**
:   Path to psql binary.

**POSTGRES_CREATEDB_BIN**
:   Path to createdb binary.

**POSTGRES_CREATEUSER_BIN**
:   Path to createuser binary.

**POSTGRES_PG_ISREADY_BIN**
:   Path to pg_isready binary.

**POSTGRES_DBAPI**
:   Python DB-API module (default: "psycopg2").

**POSTGRES_SOCKET_DIR**
:   PostgreSQL socket directory.

**POSTGRES_DEFAULT_TEXT_SEARCH_CONFIG**
:   Default text search config.

Tuning parameters:
**POSTGRES_WORK_MEM,**
**POSTGRES_SHARED_BUFFERS,**
**POSTGRES_EFFECTIVE_CACHE_SIZE,**
**POSTGRES_MAINTENANCE_WORK_MEM,**
**POSTGRES_DYNAMIC_SHARED_MEMORY_TYPE,**
**POSTGRES_MAX_CONNECTIONS,**
**POSTGRES_FSYNC,**
**POSTGRES_SYNCHRONOUS_COMMIT,**
**POSTGRES_RANDOM_PAGE_COST,**
**POSTGRES_ENABLE_HASHJOIN.**

Autovacuum settings:
**POSTGRES_AUTOVACUUM,**
**POSTGRES_AUTOVACUUM_WORK_MEM,**
**POSTGRES_AUTOVACUUM_NAPTIME,**
**POSTGRES_AUTOVACUUM_MAX_WORKERS,**
**POSTGRES_AUTOVACUUM_FREEZE_MAX_AGE,**
**POSTGRES_AUTOVACUUM_VACUUM_THRESHOLD,**
**POSTGRES_AUTOVACUUM_ANALYZE_THRESHOLD.**

Localization:
**POSTGRES_LC_TIME,**
**POSTGRES_LC_NUMERIC,**
**POSTGRES_LC_MESSAGES,**
**POSTGRES_LC_MONETARY,**
**POSTGRES_DATESTYLE,**
**POSTGRES_TIMEZONE,**
**POSTGRES_LOG_TIMEZONE.**

Custom config can be saved to
/etc/otpme/postgresql.conf.

### MySQL

**MYSQL_DBAPI**
:   Python DB-API module (e.g. "cymysql").

**MYSQL_BIN**
:   Path to mysql binary.

**MYSQLD_BIN**
:   Path to mysqld binary.

**MYSQL_ADMIN_BIN**
:   Path to mysqladmin binary.

**MYSQL_INSTALL_DB**
:   Path to mysql_install_db binary.

**MYSQL_SOCKET_DIR**
:   MySQL socket path.

Tuning parameters:
**MYSQL_MAX_CONNECTIONS,**
**MYSQL_KEY_BUFFER_SIZE,**
**MYSQL_THREAD_STACK,**
**MYSQL_MAX_ALLOWED_PACKET,**
**MYSQL_THREAD_CACHE_SIZE,**
**MYSQL_QUERY_CACHE_LIMIT,**
**MYSQL_QUERY_CACHE_SIZE,**
**MYSQL_EXPIRE_LOGS_DAYS,**
**MYSQL_MAX_BINLOG_SIZE,**
**MYSQL_CHARACTER_SET_SERVER,**
**MYSQL_COLLATION_SERVER,**
**MYSQL_MYISAM_RECOVER_OPTIONS.**

Custom config can be saved to
/etc/otpme/mysql.conf.

## CACHE

**CACHE**
:   Cache daemon: "redis", "memcached" or "memcachedb". Note that memcachedb stores sensitive data on disk. Run "otpme-tool cache stop" before changing this.

**AUTOSTART_CACHE**
:   Autostart cache on daemon start.

**FLUSH_CACHE_ON_START**
:   Flush cache on daemon start.

**OBJECT_CACHES**
:   Comma separated list of object_type:cache_size pairs (e.g. "user:2048,group:512").

**PICKLE_CACHE_MODULE**
:   Pickle module for caching: "pickle" or "larch".

### Redis

**REDIS_CLI_BIN**
:   Path to redis-cli binary.

**REDIS_SERVER_BIN**
:   Path to redis-server binary.

**REDIS_MAXMEMORY**
:   Maximum memory for Redis (e.g. "128M").

**REDIS_MAXMEMORY_POLICY**
:   Eviction policy: "lru" (volatile-lru) or "lfu" (volatile-lfu, requires Redis 4.0+).

**REDIS_MAXMEMORY_SAMPLES**
:   LRU samples count.

**REDIS_LFU_DECAY_TIME**
:   LFU decay time.

**REDIS_LFU_LOG_FACTOR**
:   LFU log factor.

**REDIS_LOGLEVEL**
:   Redis log level (e.g. "notice").

**REDIS_DATABASES**
:   Number of Redis databases.

**REDIS_SOCKET**
:   Redis socket path.

**REDIS_PERSISTENCE**
:   Enable Redis persistence. Note: stores sensitive data on disk.

**REDIS_CACHE_DIR**
:   Redis cache directory.

Custom config can be saved to
/etc/otpme/redis.conf.

### Memcached

**MEMCACHED_BIN**
:   Path to memcached binary.

**MEMCACHED_MAXMEM**
:   Maximum memory in MB.

**MEMCACHED_THREADS**
:   Number of threads.

**MEMCACHED_MAX_OBJECT_SIZE**
:   Maximum object size (e.g. "8m"). Increase if role/group objects grow large.

**MEMCACHED_SOCKET**
:   Memcached socket path.

**MEMCACHED_OPTS**
:   Full custom command line options. If set, all other memcached options are ignored.

### Memcachedb

**MEMCACHEDB_BIN**
:   Path to memcachedb binary.

**MEMCACHEDB_MAXMEM**
:   Maximum memory in MB.

**MEMCACHEDB_THREADS**
:   Number of threads.

**MEMCACHEDB_CACHE_DIR**
:   Memcachedb cache directory.

**MEMCACHEDB_SOCKET**
:   Memcachedb socket path.

**MEMCACHEDB_OPTS**
:   Full custom command line options. If set, all other memcachedb options are ignored.

## FREERADIUS

**START_FREERADIUS**
:   Start freeradius with OTPme.

**FREERADIUS_BIN**
:   Path to freeradius binary.

**RADIUS_CACHE_TIME**
:   Radius cache time in seconds.

**USE_RADIUS_MOD**
:   Use OTPme radius module.

**RADIUS_START_SERVERS**
:   Number of start servers.

**RADIUS_MAX_SERVERS**
:   Maximum number of servers.

**RADIUS_MIN_SPARE_SERVERS**
:   Minimum spare servers.

**RADIUS_MAX_SPARE_SERVERS**
:   Maximum spare servers.

## ENCRYPTION

**KEY_COMMAND**
:   Command or path to get the encryption key. Can be a file path (file:///path/to/key) or a command that outputs the key to stdout.

**MASTER_KEY_HASH_TYPE**
:   Hash type for generating master key from password (e.g. "Argon2_i").

**OFFLINE_TOKEN_HASH_TYPE**
:   Hash type for offline token encryption key derivation.

**OBJECT_EXPORT_HASH_TYPE**
:   Hash type for object export encryption key derivation.

## SSL

**SSL_SITE_CERT_FILE**
:   Path to site SSL certificate (default: /etc/otpme/ssl/site_cert.pem).

**SSL_CERT_FILE**
:   Path to SSL certificate (default: /etc/otpme/ssl/cert.pem).

**SSL_KEY_FILE**
:   Path to SSL private key (default: /etc/otpme/ssl/key.pem).

**SSL_CA_FILE**
:   Path to CA certificate (default: /etc/otpme/ssl/ca.pem).

**HOST_KEY_FILE**
:   Path to host/node RSA key file (default: /etc/otpme/ssl/hostkey.pem).

## DIRECTORIES

**DATA_DIR**
:   Directory for object configs (default: /var/lib/otpme).

**SPOOL_DIR**
:   Directory for sessions etc. (default: /var/spool/otpme).

**CACHE_DIR**
:   Directory for cached logins etc. (default: /var/cache/otpme).

**RUN_DIR**
:   Directory for pidfiles and sockets (default: /var/run/otpme).

**LOG_DIR**
:   Directory for logfiles (default: /var/log/otpme).

**MOUNT_ROOT_DIR**
:   Mount root directory (default: /otpme).

## DNS

**LOGIN_USE_DNS**
:   Use DNS to get login realm/site. Required for cross-site login. DNS records needed:
```
  _otpme-realm    TXT "realm.example.com"
  _otpme-site     TXT "sitename"
  _otpme-login    SRV 10 1 2020 login.example.com.
  _otpme-join     SRV 10 1 2024 login.example.com.
```

**USE_DNS**
:   Use DNS to resolve site address. If False, the configured site IP is used directly.

## LOGIN

**VALID_LOGIN_USERS**
:   Comma separated list of users allowed to login. Optionally with UUID (username:uuid).

**DENY_LOGIN_USERS**
:   Comma separated list of users denied from login. Optionally with UUID (username:uuid).

**LOGOUT_PASS_LEN**
:   Length of Session-Logout-Password (SLP).

## SIGNERS

**FORCE_TOKEN_SIGNERS**
:   If True (default), user-defined token signers are ignored. If False, users can define their own. Can also be a comma separated list of usernames whose private signers are ignored.

**FORCE_KEY_SCRIPT_SIGNERS**
:   Same rules as FORCE_TOKEN_SIGNERS, for key script signers.

**FORCE_AGENT_SCRIPT_SIGNERS**
:   Same rules as FORCE_TOKEN_SIGNERS, for agent script signers.

## SCRIPTS

**ROOT_SCRIPT_USER**
:   User to run root scripts as (default: "nobody").

**ROOT_SCRIPT_GROUP**
:   Group to run root scripts as (default: "nogroup").

## PAM LOGGING

**PAM_USE_SYSLOG**
:   Log PAM events to syslog.

**PAM_USE_SYSTEMD**
:   Log PAM events to systemd journal.

**PAM_USE_LOGFILE**
:   Log PAM events to logfile.

**PAM_LOGFILE**
:   PAM logfile path (default: /var/log/otpme/pam.log).

**RADIUS_MOD_LOGFILE**
:   Radius module logfile path (default: /var/log/otpme/radius-module.log).

## AUDIT LOG

**AUDIT_LOG_ENABLED**
:   Enable audit logging.

**AUDIT_LOG_FACILITY**
:   Syslog facility for audit log (default: "DAEMON").

**AUDIT_LOG_SERVER**
:   Audit log server address (e.g. "host:port").

**AUDIT_LOG_PROTOCOL**
:   Audit log protocol: "syslog" or "relp".

**AUDIT_LOG_USE_TLS**
:   Enable TLS for audit log transport.

**AUDIT_LOG_CA_CERT**
:   CA certificate for audit log TLS.

**AUDIT_LOG_USE_CLIENT_CERT**
:   Use client certificate for audit log.

**AUDIT_LOG_CERT**
:   Client certificate for audit log.

**AUDIT_LOG_KEY**
:   Client key for audit log.

## SYSLOG

**SYSLOG_ENABLED**
:   Enable syslog logging.

**SYSLOG_FACILITY**
:   Syslog facility (default: "DAEMON").

**SYSLOG_SERVER**
:   Syslog server address.

**SYSLOG_PROTOCOL**
:   Syslog protocol: "syslog" or "relp".

**SYSLOG_USE_TLS**
:   Enable TLS for syslog transport.

**SYSLOG_CA_CERT**
:   CA certificate for syslog TLS.

**SYSLOG_USE_CLIENT_CERT**
:   Use client certificate for syslog.

**SYSLOG_CERT**
:   Client certificate for syslog.

**SYSLOG_KEY**
:   Client key for syslog.

## SYNCHRONIZATION

**SYNC_MEM_CACHE**
:   Cache objects in memory while syncing.

**SYNC_INTERVAL**
:   Interval in seconds between sync attempts with master node.

**SYNC_RETRY_INTERVAL**
:   Retry interval in seconds if sync fails.

**SYNC_RETRY_COUNT**
:   Number of retries to reach consistent state before waiting for SYNC_INTERVAL.

**SYNC_IGNORE_CHANGED_OBJECTS**
:   If True, sync objects as received even if they changed during sync. May lead to inconsistent state but helps when objects change frequently.

## DAEMON

**TWO_NODE_TIMEOUT**
:   Seconds to wait for second node in two-node clusters.

**CONTROLD_HEARTBEAT_INTERVAL**
:   Interval in seconds for heartbeat messages to child daemons.

**CONTROLD_HEARTBEAT_TIMEOUT**
:   Timeout in seconds for heartbeat messages.

**CONTROLD_HEARTBEAT_RETRY_INTERVAL**
:   Retry interval in seconds for failed heartbeat messages.

**CONTROLD_HEARTBEAT_RETRY**
:   Max retries before restarting a child daemon.

**INTER_DAEMON_COMM_TIMEOUT**
:   Timeout for inter-daemon communication. Increase if daemons report "not responding" under high load.

**BACKEND_POLICY_INTERVAL**
:   Max interval in seconds the backend executes object policies (e.g. autodisable).

**RELOAD_CONFIG_INTERVAL**
:   Interval in seconds to check for config file changes.

## AGENT

**AGENT_CONNECTION_IDLE_TIMEOUT**
:   Seconds before otpme-agent closes idle daemon connections.

**AGENT_KEEPALIVE_INTERVAL**
:   Interval in seconds for keepalive messages to daemons.

## NETWORK

**SOCKET_SEND_BUFFER**
:   Socket send buffer size in bytes. Should be high (e.g. 100 MiB) to speed up the OTPme FUSE module.

**SOCKET_RECEIVE_BUFFER**
:   Socket receive buffer size in bytes.

**POSIX_MSGSIZE_MAX**
:   Max POSIX message queue message size. Set to "auto" to read from /proc/sys/fs/mqueue/msgsize_max.

**RLIMIT_MSGQUEUE**
:   Max POSIX message queue size (see getrlimit(2)). Increase for large installations.

## STORAGE

**OBJECT_JSON_COMPRESSSION**
:   Compression for object JSON files (e.g. "lz4").

**PRETTIFY_OBJECT_JSON**
:   Pretty-print object JSON files.

## LDAP

**LDAP_VERIFY_ACLS**
:   Verify ACLs for LDAP access.

## LOGGING

**LOGLEVEL**
:   Log level: CRITICAL, ERROR, WARNING, INFO or DEBUG.

**LOG_AUTH_DATA**
:   Log authentication data (passwords, challenge/response). Can be True, False or a comma separated list of usernames.

**TRACEBACKS**
:   Print Python tracebacks.

**SHOW_JOB_TITLE**
:   Show job title in process name.

## FILES

*/etc/otpme/otpme.conf*
:   Main configuration file.

*/etc/otpme/otpme.conf.dist*
:   Distribution template.

*/etc/otpme/otpme.key*
:   Default encryption key file.

*/etc/otpme/redis.conf*
:   Custom Redis configuration.

*/etc/otpme/postgresql.conf*
:   Custom PostgreSQL configuration.

*/etc/otpme/mysql.conf*
:   Custom MySQL configuration.

## SEE ALSO

[otpme(1)](otpme.md),
[otpme(7)](otpme.7.md)

## AUTHOR

the2nd <the2nd@otpme.org>

## NOTE

This manual page was created with AI assistance.

## COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
