# NAME

otpme.conf - OTPme configuration file

# SYNOPSIS

*/etc/otpme/otpme.conf*  
*\~/.otpme/otpme.conf*

# DESCRIPTION

**otpme.conf** sets how OTPme runs on this system: the index and cache,
the daemons, logging, backups and more. The settings of the realm, its
sites and objects are not here; they are config parameters of the
objects, see **otpme**(7).

Each line is *NAME*=*value*, e.g.

> **LOGLEVEL="INFO"**

The value can be in double or single quotes, or without them. **True**
and **False** are yes and no, a list is comma separated. A line that
starts with **\#** is a comment, and so is the rest of a line after a
value and a **\#**. An empty value is the same as no line: the default
stays. A line OTPme cannot read stops it with a message that names the
line. A parameter it does not know gives a message and is ignored.

A command reads the file each time it runs. The daemons read it when
they start, and again on **otpme-controld reload**.

A user can set some parameters for themselves, in
*\~/.otpme/otpme.conf*; that one wins for them. Those parameters say so
below.

*/etc/otpme/otpme.conf.dist* has all parameters with a comment on each,
see **FILES**.

# GENERAL

**BIN_DIR**  
The directory of the OTPme commands (default: */usr/local/bin*).
**otpme-agent** and **otpme-controld** are started from there, and
scripts find the commands there: it comes first in their **PATH** and is
in **OTPME_BIN_DIR**.

**TIMEZONE**  
The time zone of the certificates a CA issues (default:
**Europe/Berlin**).

**LANGUAGE**  
The language of the output (default: **env**). **env** takes it from
**LC_ALL**, **LC_MESSAGES** or **LANG**, the first one set; without any
it is **en**. There are **en**, **de**, **es**, **fr** and **it**; any
other gives a message and **en**. What the servers answer is in the
language of the user, if one was set with **otpme-user language**. A
user can set it in *\~/.otpme/otpme.conf* as well.

**LOG_LANGUAGE**  
The language of the log messages (default: **en**).

**USER**, **GROUP**  
The system user and group that own the files of OTPme and that the
daemons run as (default: **otpme** and **otpme**).

**HANDLE_FILES_DIRS**  
Whether OTPme makes the directories and files it needs and sets their
owner and mode (default: **True**). With **False** the package or the
administrator has to see to that; a missing one is then an error.

**PINENTRY**  
The pinentry program (default: */usr/bin/pinentry*). **otpme-agent**
asks for the PIN and for a confirmation with it, and **otpme-pinentry**
wraps it. A user can set it in *\~/.otpme/otpme.conf* as well.

**USE_MGMTD_SOCKET**  
Whether a command goes to the local mgmtd through its socket when nobody
is logged in, as the global option **--socket** does (default:
**False**). Without it, such a command fails with "Not logged in". Only
on a node, where mgmtd runs. A user can set it in *\~/.otpme/otpme.conf*
as well.

**USE_PAGER**  
Whether long output of a command is shown through a pager, only ever on
a terminal (default: **auto**). **auto** pages when the output does not
fit the terminal, **True** always, **False** never. The pager is the one
**PAGER** names, else **pager** or **less**. A user can set it in
*\~/.otpme/otpme.conf* as well.

# INDEX DATABASE

The index is the database next to the object files that OTPme searches.
It can always be built again from the files, see **index rebuild** in
**otpme-tool**(1). PostgreSQL and MySQL run as a server of their own,
with their files in */var/lib/otpme/index/* and a socket in
*/var/run/otpme/sockets/*; OTPme starts it and writes its configuration.

**INDEX**  
The type: **sqlite3**, **postgres** or **mysql**. It has to be set;
without it no command runs. SQLite is meant for hosts with few objects;
do not use it on nodes. Run **otpme-tool index stop** before changing
it. The index of the old type is not carried over.

**AUTOSTART_INDEX**  
Whether **otpme-controld** starts the PostgreSQL or MySQL server when it
starts, and stops it when it stops (default: **True**). With **False**
the server has to run already, else the daemons do not start: "Index not
started". The global option **--no-index-start** does the same for one
start. SQLite needs no server.

## SQLite3

The index is the file */var/lib/otpme/index/objects.sqlite*. It is meant
for hosts with few objects, not for nodes: a node holds all objects of
the site, and its daemons write to the index at the same time.

**SQLITE3_BIN**  
The **sqlite3** program that **otpme-tool index cli** opens (default:
**sqlite3**).

**SQLITE3_PRAGMA_SYNCHRONOUS**  
How often SQLite waits for the disk: **OFF**, **NORMAL**, **FULL** or
**EXTRA** (default: **OFF**). With **OFF** a crash of the machine can
damage the index; **otpme-tool index rebuild** builds it again.

## PostgreSQL

**POSTGRES_PG_CTL_BIN**, **POSTGRES_PSQL_BIN**, **POSTGRES_CREATEDB_BIN**, **POSTGRES_CREATEUSER_BIN**, **POSTGRES_PG_ISREADY_BIN**  
The PostgreSQL programs (default: **pg_ctl**, **psql**, **createdb**,
**createuser** and **pg_isready**, found in **PATH**). On Debian
**pg_ctl** is not in **PATH**: give the full path, e.g.
*/usr/lib/postgresql/15/bin/pg_ctl*.

**POSTGRES_DBAPI**  
The Python driver: **psycopg2** (default), **pg8000**, **pygresql** or
**psycopg2cffi**.

**POSTGRES_SOCKET_DIR**  
The directory of the socket (default:
*/var/run/otpme/sockets/postgres*).

These go into the *postgresql.conf* that OTPme writes, as the PostgreSQL
setting of the same name in lower case: **POSTGRES_WORK_MEM** is
**work_mem**. What they do is in the PostgreSQL documentation. The
defaults: **POSTGRES_MAX_CONNECTIONS** 500, **POSTGRES_SHARED_BUFFERS**
512MB, **POSTGRES_WORK_MEM** 128MB, **POSTGRES_MAINTENANCE_WORK_MEM**
256MB, **POSTGRES_EFFECTIVE_CACHE_SIZE** 512MB,
**POSTGRES_DYNAMIC_SHARED_MEMORY_TYPE** posix, **POSTGRES_FSYNC** on,
**POSTGRES_SYNCHRONOUS_COMMIT** off, **POSTGRES_RANDOM_PAGE_COST** 1.0,
**POSTGRES_ENABLE_HASHJOIN** off, **POSTGRES_AUTOVACUUM** on,
**POSTGRES_AUTOVACUUM_WORK_MEM** -1, **POSTGRES_AUTOVACUUM_NAPTIME**
1min, **POSTGRES_AUTOVACUUM_MAX_WORKERS** 5,
**POSTGRES_AUTOVACUUM_FREEZE_MAX_AGE** 100000,
**POSTGRES_AUTOVACUUM_VACUUM_THRESHOLD** 50,
**POSTGRES_AUTOVACUUM_ANALYZE_THRESHOLD** 50, **POSTGRES_DATESTYLE**
"iso, mdy", **POSTGRES_TIMEZONE** and **POSTGRES_LOG_TIMEZONE**
Europe/Berlin, **POSTGRES_DEFAULT_TEXT_SEARCH_CONFIG**
pg_catalog.english.

A file */etc/otpme/postgresql.conf* is used instead of the one OTPme
writes. Then none of the settings above apply.

## MySQL

**MYSQLD_BIN**, **MYSQL_BIN**, **MYSQL_ADMIN_BIN**, **MYSQL_INSTALL_DB**  
The MySQL programs (default: */usr/sbin/mysqld*, then **mysql**,
**mysqladmin** and **mysql_install_db**, found in **PATH**).

**MYSQL_DBAPI**  
The Python driver: **pymysql** (default), **mysqldb** or **cymysql**.

**MYSQL_SOCKET_DIR**  
The directory of the socket *mysqld.sock* (default:
*/var/run/otpme/sockets/mysql*).

These go into the *mysql.cnf* that OTPme writes, as the MySQL setting of
that name: **MYSQL_KEY_BUFFER_SIZE** is **key_buffer_size**,
**MYSQL_CHARACTER_SET_SERVER** is **character-set-server**. The
defaults: **MYSQL_MAX_CONNECTIONS** 512, **MYSQL_KEY_BUFFER_SIZE** 160M,
**MYSQL_THREAD_STACK** 192K, **MYSQL_MAX_ALLOWED_PACKET** 512M,
**MYSQL_THREAD_CACHE_SIZE** 8, **MYSQL_QUERY_CACHE_LIMIT** 10M,
**MYSQL_QUERY_CACHE_SIZE** 160M, **MYSQL_EXPIRE_LOGS_DAYS** 10,
**MYSQL_MAX_BINLOG_SIZE** 100M, **MYSQL_BINLOG_FORMAT** ROW,
**MYSQL_CHARACTER_SET_SERVER** utf8mb4, **MYSQL_COLLATION_SERVER**
utf8mb4_general_ci, **MYSQL_MYISAM_RECOVER_OPTIONS** BACKUP.

**MYSQL_BINLOG_FORMAT** must be **ROW** or **MIXED**. The index reads
with READ COMMITTED, and MySQL refuses every write with **STATEMENT**.

A file */etc/otpme/mysql.cnf* is used instead of the one OTPme writes.
Then none of the settings above apply.

# CACHE

The cache holds what the processes of a host or node share, in Redis or
memcached: the state of the cluster and of running jobs, and the results
of some lookups, such as the roles and tokens of a user and password
hashes. It runs as a server of its own with a socket in
*/var/run/otpme/sockets/*, and OTPme starts it and writes its
configuration. Objects and search results stay in the memory of each
process, see **OBJECT_CACHES**; sessions are files like the objects.

**CACHE**  
The cache server: **redis** (default) or **memcached**. Run **otpme-tool
cache stop** before changing it.

**AUTOSTART_CACHE**  
Whether **otpme-controld** starts the cache server when it starts, and
stops it when it stops (default: **True**). With **False** the server
has to run already, else the daemons do not start: "Cache not started".
The global option **--no-cache-start** does the same for one start.

**FLUSH_CACHE_ON_START**  
Whether **otpme-controld** empties the cache when it starts (default:
**True**). With **False** the global option **--cache-flush** does it
for one start.

**OBJECT_CACHES**  
How many objects of a type each process keeps in its own memory, as
***type*:*count*** pairs separated by commas, e.g.
**user:2048,group:512**. When a type is full, the quarter used longest
ago goes. The defaults: **user** and **token** 10240, **script** 512,
**dictionary** 128, every other type 1024. A type not named keeps its
default.

## Redis

**REDIS_SERVER_BIN**, **REDIS_CLI_BIN**  
The Redis programs (default: **redis-server** and **redis-cli**, found
in **PATH**). **otpme-tool cache cli** opens **redis-cli**.

**REDIS_SOCKET**  
The socket (default: */var/run/otpme/sockets/redis.sock*). Redis listens
on no TCP port.

**REDIS_MAXMEMORY**  
How much memory Redis may use (default: **128M**).

**REDIS_MAXMEMORY_POLICY**  
What goes when that is full: **lru**, the entries used longest ago
(Redis **volatile-lru**), or **lfu**, the ones used least often
(**volatile-lfu**) (default: **lru**).

**REDIS_MAXMEMORY_SAMPLES**  
With **lru**: how many entries Redis looks at to pick one (default:
**5**).

**REDIS_LFU_LOG_FACTOR**, **REDIS_LFU_DECAY_TIME**  
With **lfu**: Redis **lfu-log-factor** and **lfu-decay-time** (default:
**10** and **1**).

**REDIS_LOGLEVEL**  
The log level of Redis, written to */var/log/otpme/redis.log* (default:
**notice**).

**REDIS_DATABASES**  
How many databases Redis has (default: **16**).

**REDIS_PERSISTENCE**  
Whether Redis writes the cache to disk, in **REDIS_CACHE_DIR** (default:
**False**). The cache holds password hashes; with **True** they are on
the disk. With **False** OTPme also turns it off on a running Redis.

**REDIS_CACHE_DIR**  
Where Redis writes with **REDIS_PERSISTENCE** (default:
*/var/cache/otpme/redis*).

A file */etc/otpme/redis.conf* is used instead of the one OTPme writes.
Then none of the settings above apply, but **REDIS_PERSISTENCE** still
does.

## Memcached

**MEMCACHED_BIN**  
The memcached program (default: **memcached**, found in **PATH**).

**MEMCACHED_MAXMEM**  
How much memory memcached may use, in MB (default: **128**).

**MEMCACHED_THREADS**  
The threads of memcached (default: **32**).

**MEMCACHED_MAXCONN**  
How many connections memcached takes (default: **4096**). The default of
memcached itself, 1024, is not enough here: the connection pool holds
one connection per thread and process and never gives it back, so every
daemon, every ldapd worker and every forked child adds to the count.
Once the limit is reached memcached turns new connections away, which
reaches the client as a connection reset on a cache that is running
fine:

**Memcache get error: ... CONNECTION FAILURE(Connection reset by peer)**

**MEMCACHED_MAX_OBJECT_SIZE**  
The largest entry memcached takes (default: **8m**). Make it larger if
roles or groups with many members grow beyond it.

**MEMCACHED_SOCKET**, **MEMCACHED_PIDFILE**  
The socket and the PID file (default:
*/var/run/otpme/sockets/memcached.sock* and
*/var/run/otpme/pidfiles/memcached.pid*). Memcached listens on no TCP or
UDP port.

**MEMCACHED_OPTS**  
The whole command line of memcached. All other memcached settings above
are then ignored, so it has to give **-s** with the socket and **-P**
with the PID file: OTPme looks for memcached there.

# FREERADIUS

On a node OTPme runs a FreeRADIUS server of its own on port 1812, with
its configuration in */var/run/otpme/freeradius/*. It runs only while
the node is enabled and the cluster has a quorum; otherwise it is
stopped. The RADIUS clients are the OTPme clients, see
**otpme-client**(1).

**otpme-controld** starts it as root, and FreeRADIUS then changes to its
own user. With the module (**USE_RADIUS_MOD**) that is
**FREERADIUS_USER**: it has no access to the objects of OTPme and gets
the client of a request and the session of a cached login from
**otpme-hostd**. Without the module it is the OTPme user, because
**otpme-auth** reads the auth cache of the node. The configuration
directory and its files belong to the OTPme user and to the group of
FreeRADIUS, which may only read them.

**START_FREERADIUS**  
Whether the node runs FreeRADIUS (default: **True**).

**FREERADIUS_BIN**  
The FreeRADIUS program (default: */usr/sbin/freeradius*).

**FREERADIUS_USER**, **FREERADIUS_GROUP**  
The user and group FreeRADIUS runs as with the module (default:
**freerad** and **freerad**).

**FREERADIUS_LOG_DIR**  
Where FreeRADIUS writes *radius.log* with the module, and the module its
audit log *audit.log* (default: */var/log/freeradius*). The module does
not send its audit log to **AUDIT_LOG_SERVER**, because
**FREERADIUS_USER** may not read the certificate and key of the node;
what authd does for it goes there as always. It is made for
**FREERADIUS_USER** when it is missing. Without the module *radius.log*
is in the log directory of OTPme.

**USE_RADIUS_MOD**  
Whether FreeRADIUS checks a request through the Python module of OTPme
(default: **True**). The module also adds the VLAN and the MPPE keys to
the answer. With **False** every request starts **otpme-auth verify**,
which is slower, and no VLAN is sent. Either way an answer comes from
the cache only where the client has its auth cache enabled, for its
**auth_cache_timeout**, see **THE AUTH CACHE** in **otpme-client**(1).

**RADIUS_START_SERVERS**, **RADIUS_MAX_SERVERS**, **RADIUS_MIN_SPARE_SERVERS**, **RADIUS_MAX_SPARE_SERVERS**  
The thread pool of FreeRADIUS: **start_servers**, **max_servers**,
**min_spare_servers** and **max_spare_servers** (default: **32**,
**64**, **8** and **16**).

A file */etc/otpme/freeradius/radiusd.conf* is used instead of the one
OTPme writes. Then none of the settings above apply but
**START_FREERADIUS**, **FREERADIUS_BIN** and **FREERADIUS_GROUP**, and
the user FreeRADIUS runs as is the one the file gives. The log of the
module is **RADIUS_MOD_LOGFILE**, see **PAM LOGGING**.

# HAPROXY (LDAP LOAD BALANCING)

An haproxy on the floating IP of the site spreads LDAP connections over
the ldapd of all enabled member nodes, its own one included, to the one
with the fewest connections. It runs on the node that holds the floating
IP, started and stopped by **otpme-controld** along with it, so it
follows the master to another node. When a member node comes or goes it
is reloaded without dropping a connection.

It passes the connections on as they are, LDAPS with the site
certificate, so the **dc=*client*** of a bind DN still picks the access
group. ldapd sees the address of haproxy, not that of the client.
Clients can still reach every ldapd directly on its own port, 2026.

The nodes are reached by their FQDN, so they have to resolve. Without a
site address haproxy is not started.

**START_HAPROXY**  
Whether the node runs haproxy (default: **False**; the distributed
*otpme.conf* sets **True**). haproxy has to be installed.

**HAPROXY_BIN**  
The haproxy program (default: */usr/sbin/haproxy*).

**HAPROXY_PORT**  
The port on the floating IP that clients connect to (default: **636**).
636 is where LDAP clients look for LDAPS, which is what dovecot and SOGo
want to be pointed at.

**HAPROXY_MAXCONN**  
How many connections haproxy takes at once (default: **4096**).

**HAPROXY_CHECK_INTERVAL**  
How often each node is checked with a TCP connect (default: **5s**). A
node is out after 3 failed checks and back after 2 good ones.

**HAPROXY_CONNECT_TIMEOUT**  
How long haproxy waits for a connection to an ldapd (default: **5s**).

**HAPROXY_CLIENT_TIMEOUT**, **HAPROXY_SERVER_TIMEOUT**  
How long an idle connection to the client and to the ldapd is kept
(default: **1h** and **1h**). Generous on purpose: dovecot keeps its
LDAP connection open between logins, and cutting an idle one only makes
it reconnect.

The times are in the format of haproxy, e.g. **5s**, **10m**, **1h**.

A file */etc/otpme/haproxy/haproxy.cfg* is used instead of the one OTPme
writes. Then none of the settings above apply but **START_HAPROXY** and
**HAPROXY_BIN**, and the member nodes are not added: the file has to
name them itself.

# ENCRYPTION

On a node and on a host the object files are encrypted with the master
key, a Fernet key (AES with HMAC) of 44 base64 characters.

**KEY_COMMAND**  
Where the master key comes from (default:
**file://etc/otpme/otpme.key**).

**file://*path***  
A file that holds the key. *path* is the absolute path without its first
slash: **file://etc/otpme/otpme.key** is */etc/otpme/otpme.key*.
**otpme-realm init** and the join of a host or node write it, from a
master password that is asked for, and keep its salt in
*/etc/otpme/otpme.key_salt*. **otpme-tool regen_master_key** writes it
again from the password and that salt.

*command*  
A program, with its arguments, that writes the key to stdout. OTPme then
writes no key file; the program has to give the same key every time.

**MASTER_KEY_HASH_TYPE**  
How the master key is made from the master password (default:
**Argon2_i**). The hash type is not kept with the salt: change it after
the key was made and **regen_master_key** gives another key.

**OFFLINE_TOKEN_HASH_TYPE**  
How the key that encrypts the offline login data of a user on a host is
made from their password (default: **Argon2_i**). It counts for offline
logins saved from then on. A user can set it in *\~/.otpme/otpme.conf*
as well.

**OBJECT_EXPORT_HASH_TYPE**  
How **export --password** makes its key from the password (default:
**Argon2_i**). The export keeps the salt but not the hash type:
**otpme-tool import** has to run with the same one. A user can set it in
*\~/.otpme/otpme.conf* as well.

The hash types are **Argon2_i**, **Argon2_id**, **Argon2_d** and
**PBKDF2**.

# SSL

The files a host or node gets when it joins the realm, and that hostd
keeps up to date. OTPme writes them; change the paths only to have them
somewhere else.

**SSL_CERT_FILE**, **SSL_KEY_FILE**  
The certificate of this host or node, issued by the CA of its site, and
its private key (default: */etc/otpme/ssl/cert.pem* and
*/etc/otpme/ssl/key.pem*). Daemons answer with them, and commands
connect with them, also the ones a user starts: so both are owned by
**otpme** and readable by the group **realmusers**, mode 0640.

**SSL_CA_FILE**  
The CA certificates a host or node trusts (default:
*/etc/otpme/ssl/ca.pem*), mode 0640 like the two above.

**SSL_SITE_CERT_FILE**  
The certificate of each site, one file per site (default:
*/etc/otpme/ssl/{realm}-{site}.pem*). **{realm}** and **{site}** stand
for the names: */etc/otpme/ssl/example.org-berlin.pem*. A file that is
there is kept as it is when a sync brings another certificate;
**otpme-tool sync --request-site-cert** replaces it, see
**otpme-tool**(1). Mode 0644.

**HOST_KEY_FILE**  
The RSA key a host or node authenticates itself with (default:
*/etc/otpme/ssl/hostkey.pem*). Mode 0600.

# DIRECTORIES

Where OTPme keeps its files. A change takes effect when the daemons
start again; the files that are there are not moved.

**DATA_DIR**  
The objects and what goes with them (default: */var/lib/otpme*): the
object files in *tree/*, the index in *index/*, the sessions, the trash
and the data objects such as jobs and inventories in *data/*.

**SPOOL_DIR**  
Work in progress (default: */var/spool/otpme*): open transactions, the
sync, the cluster journal and what is waiting for nsscache.

**CACHE_DIR**  
What a host keeps for itself (default: */var/cache/otpme*): the offline
logins, the nsscache files, the keys of signers, the Redis files with
**REDIS_PERSISTENCE**.

**RUN_DIR**  
PID files, sockets and locks, and the configuration OTPme writes for
FreeRADIUS and haproxy (default: */var/run/otpme*).

**LOG_DIR**  
The log files (default: */var/log/otpme*).

**MOUNT_ROOT_DIR**  
Where shares are mounted on a host (default: */otpme*), as
*\<user\>/\<realm\>/\<site\>/\<share\>*. It is owned by root and the
group **realmusers**, mode 0770.

**SHARE_ROOT**  
Where the shares of a node keep their data, for every share on this
node. Set, it counts instead of the config parameter **share_root** of
the shares, see **otpme-share**(1).

# DNS

OTPme reaches the daemons of a site by the FQDNs of the site
(**auth_fqdn**, **mgmt_fqdn**, see **otpme-site**(1)), so those have to
resolve; without them it takes the address of the site. Beyond that DNS
says where to log in and where to join, from these records in the DNS
domain of the host:

>     _otpme-realm._tcp   TXT  "example.org"
>     _otpme-site._tcp    TXT  "berlin"
>     _otpme-join._tcp    SRV  10 1 2024 login.example.org.

The domain is the FQDN of the host without its first label:
**nb1.example.org** looks in **example.org**.

**LOGIN_USE_DNS**  
Whether a login on a host goes to the realm and site the TXT records
name, instead of those the host belongs to (default: **True**). That
lets a notebook of one site log in at another. A node never asks. The
global options **--login-use-dns** and **--login-no-dns** override it
for one command.

**otpme-tool join** always asks DNS, in the domain it is given, else in
***site*.*realm***, else in the domain of the host: the SRV record for
joind (unless **--joind-uri** names it), else the address of the domain
itself with port 2024, and the TXT records for the realm and site it is
not given.

# LOGIN

**VALID_LOGIN_USERS**, **DENY_LOGIN_USERS**  
Which users may log in on this host, as names separated by commas
(default: empty, everybody). An entry ***name*:*uuid*** also matches the
user with that UUID, so a renamed user stays matched. A user in
**DENY_LOGIN_USERS** is refused, also when **VALID_LOGIN_USERS** names
them; with **VALID_LOGIN_USERS** set, everybody else is refused. It
counts for a login through pam_otpme, and the SSH keys of a refused user
are not written to their *authorized_keys*.

**ALLOW_DYNAMIC_GROUPS**, **DENY_DYNAMIC_GROUPS**  
Which dynamic groups a user gets at login, as names separated by commas
(default: empty, all). A dynamic group is a group of this host that
pam_otpme adds the user to: those of the host and those of the login
token and its roles, see **add_dynamic_group** in **otpme-role**(1). A
group in **DENY_DYNAMIC_GROUPS** is left out; with
**ALLOW_DYNAMIC_GROUPS** set, only the groups it names are added.
**ALLOW_DYNAMIC_GROUPS** **False** adds none. A group that does not
exist on the host is left out with a warning.

# SIGNERS

A signer is a user or a role whose signatures this host accepts, see
**add_signer** in **otpme-tool**(1). The signers of the host check token
signatures (e.g. whether an SSH token is signed for a group), the key
script and the agent script. A user can have private signers of their
own for these three, in *\~/.otpme/signers/* (**add_signer --private**).
These parameters say whether those count. A disabled signer never
counts.

**FORCE_TOKEN_SIGNERS**, **FORCE_KEY_SCRIPT_SIGNERS**, **FORCE_AGENT_SCRIPT_SIGNERS**  
For token signatures, the key script and the agent script (default:
**True**):

**True**  
Only the signers of the host count; private signers are ignored.

**False**  
A user who has private signers gets them instead of those of the host.

*user*\[**,*user***\]...  
Only the signers of the host count for these users; every other user
gets their private signers, where they have any.

# SCRIPTS

scriptd runs the scripts of a node: authorization scripts of users and
tokens, the scripts of **script_otp** and **script_static** tokens, push
scripts, share scripts and the vote script. It never runs a script as
root or as **USER**/**GROUP**. An authorization script, the script of a
**script_otp** or **script_static** token and a push script run as the
user they are for and with the group of that user. The authorization
script of a user and a push script also get the other groups of the
user. A share script and the vote script run as the user and group
below.

**ROOT_SCRIPT_USER**, **ROOT_SCRIPT_GROUP**  
The user and group a script runs as instead of root or
**USER**/**GROUP** (default: **nobody** and **nogroup**).

# PAM LOGGING

Where pam_otpme writes its log, see **pam_otpme**(8). It uses the first
of **PAM_USE_LOGFILE**, **PAM_USE_SYSLOG** and **PAM_USE_SYSTEMD** that
is **True**. If none is, it logs nothing. The level is **LOGLEVEL**.

**PAM_USE_LOGFILE**  
Write to **PAM_LOGFILE** (default: **False**). A screen unlock runs
pam_otpme as the user, who can not write to that file; pam_otpme then
uses the next one that is **True**.

**PAM_LOGFILE**  
The log file (default: */var/log/otpme/pam.log*).

**PAM_USE_SYSLOG**  
Send to the local syslog (*/dev/log*), with facility **LOCAL7**
(default: **False**).

**PAM_USE_SYSTEMD**  
Send to the systemd journal (default: **True**).

**RADIUS_MOD_LOGFILE**  
The log file of the FreeRADIUS module of OTPme, see **FREERADIUS**
(default: */var/log/freeradius/radius-module.log*). It has to be a file
**FREERADIUS_USER** may write. The module always writes there.

# AUDIT LOG

Every daemon of OTPme writes an audit log: each change of an object (who
did it, from which client, in which session, and what), and the logins,
sessions and other events of its protocols. The agent writes none.

Without **AUDIT_LOG_ENABLED** and **AUDIT_LOG_SERVER** the audit log
goes to *audit.log* in **LOG_DIR**. With both, it goes to that syslog
server instead. An entry the server does not get is kept in *audit_log/*
in **SPOOL_DIR**, and hostd sends it again every 60 seconds, starting
with **LOG_RESEND:** and the time it was written.

**AUDIT_LOG_ENABLED**  
Send the audit log to **AUDIT_LOG_SERVER** (default: **False**).

**AUDIT_LOG_SERVER**  
The syslog server, as ***host*:*port*** for TCP, or as *host* for UDP on
port 514 (default: none). TLS and RELP need the port.

**AUDIT_LOG_PROTOCOL**  
**syslog** (default) or **relp**.

**AUDIT_LOG_FACILITY**  
The syslog facility, e.g. **DAEMON**, **AUTH** or **LOCAL0** to
**LOCAL7** (default: **DAEMON**).

**AUDIT_LOG_USE_TLS**  
Talk TLS to the server (default: **False**). Its certificate must be
signed by **AUDIT_LOG_CA_CERT** and hold the host name of
**AUDIT_LOG_SERVER**. Without **AUDIT_LOG_CA_CERT** the audit log goes
to the file.

**AUDIT_LOG_CA_CERT**  
The CA certificate that checks the server (default: none).

**AUDIT_LOG_USE_CLIENT_CERT**  
With TLS, also show the server a certificate of this host:
**AUDIT_LOG_CERT** and **AUDIT_LOG_KEY** (default: **False**). Without
them the audit log goes to the file.

**AUDIT_LOG_CERT**, **AUDIT_LOG_KEY**  
The client certificate and its key (default: none).

# SYSLOG

With **SYSLOG_ENABLED** and **SYSLOG_SERVER** the daemons send their log
to that syslog server instead of their log files in **LOG_DIR**. A
daemon started with **-d**, and **otpme-realm init**, still log to the
terminal. A message the server does not get is lost: unlike the audit
log it is not kept. Without **SYSLOG_CA_CERT**, or without
**SYSLOG_CERT** or **SYSLOG_KEY** where they are needed, the daemons log
to their files. The parameters work like those of **AUDIT LOG**:

**SYSLOG_ENABLED**  
Send the log to **SYSLOG_SERVER** (default: **False**).

**SYSLOG_SERVER**  
***host*:*port*** for TCP, or *host* for UDP on port 514 (default:
none). TLS and RELP need the port.

**SYSLOG_PROTOCOL**  
**syslog** (default) or **relp**.

**SYSLOG_FACILITY**  
The syslog facility (default: **DAEMON**).

**SYSLOG_USE_TLS**  
Talk TLS to the server, checked with **SYSLOG_CA_CERT** (default:
**False**).

**SYSLOG_CA_CERT**  
The CA certificate that checks the server (default: none).

**SYSLOG_USE_CLIENT_CERT**  
With TLS, also show the server **SYSLOG_CERT** and **SYSLOG_KEY**
(default: **False**).

**SYSLOG_CERT**, **SYSLOG_KEY**  
The client certificate and its key (default: none).

# SYNCHRONIZATION

hostd syncs the objects of this host, and its other data, from the
master node of its site. On the master node, hostd syncs from the master
nodes of the other sites. It also starts a sync when it is told to, see
**sync** in **otpme-tool**(1).

**SYNC_INTERVAL**  
Seconds from one sync to the next (default: **180**).

**SYNC_RETRY_INTERVAL**  
Seconds until a sync that failed is tried again (default: **10**).

**SYNC_RETRY_COUNT**  
How many runs one sync may take to reach the state of the master node
(default: **5**). An object that changes on the master node while it is
fetched makes another run. After the last one the sync counts as failed.

**SYNC_IGNORE_CHANGED_OBJECTS**  
Keep an object as it came, even if it changed on the master node while
it was fetched, and make no further run for it (default: **False**).
This helps when objects change faster than a sync can follow; the
objects here can then be out of step with each other until the next
sync. For one sync, use **do_sync --ignore-changed-objects** in
**otpme-tool**(1).

**PIN_HOST_KEYS**  
If True, write down the public key of every host that is synced here,
and hold the host to it.

A remote access session is checked against the key a host was joined
with, read from this host's copy of the tree. Whoever can change the
tree can change that key. With this, they cannot change it here: the key
written down is the one a session is checked against.

The first key of a host is written down by the sync that brings it — it
comes from the realm, not from the host, so there is nobody to ask. A
key that differs from the one written down does not replace it. The sync
says so in its log, and you take the new key over by hand as root:

> **otpme-tool update_host_keys**

Until then a session to that host does not open. A host that was never
synced here has no key written down and gets no session either.

The sync never removes a key it wrote down, not even the key of a host
that is gone. Else whoever controls a node could delete a host and add
it again, with the same UUID and a key of their own. **otpme-tool
update_host_keys** removes the keys of hosts that are gone.

Without it a host gets only its own host object, and the copies of the
other hosts it had are removed. So a remote access session from a host
to another host needs this. A session to a node works either way,
because a host gets all nodes.

Default False, because it means a command for every host whose key
changes. See **otpme-shell**(1) and **otpme-tool**(1).

**PIN_USER_KEYS**  
If True, write down the encrypt public key of every user that is synced
here, and hold the user to it. Only on hosts.

**otpme-pass** encrypts the key of a password for every member, with the
encrypt public key of that member. That key comes from the nodes.
Whoever runs a node could hand in a key of their own for a member, and
read every password that is written after that. With this, the key from
the nodes must be the one written down here, or the member gets no key
from this host.

It works like **PIN_HOST_KEYS**: the sync writes down the first key of a
user, a key that differs does not replace it, and you take the new key
over by hand as root:

> **otpme-tool update_user_keys**

The sync never removes a key it wrote down, not even the key of a user
that is gone. **update_user_keys** removes those as well.

A member whose user this host does not get has no key written down here,
and gets no key from this host.

Default False. See **otpme-pass**(1).

# DAEMON

**MASTER_FAILOVER_SYNC**  
Sync once more before the master role moves on request, see
**master_failover** in **otpme-cluster**(1) (default: **False**). The
node that takes the role syncs the data objects, the sessions and then
the objects from the old master node. A sync that fails is tried again
every second, until it works.

**TWO_NODE_TIMEOUT**  
Seconds a node of a two-node site waits for the other node when clusterd
starts (default: **30**). If the other node does not come in that time,
the node elects a master node alone. See **TWO NODES** in
**otpme-cluster**(1).

**CONTROLD_HEARTBEAT_INTERVAL**  
Seconds from one check of the daemons to the next (default: **15**). At
each check controld sends a heartbeat to each of its daemons, and starts
one that is not running.

**CONTROLD_HEARTBEAT_TIMEOUT**  
Seconds controld waits for the answer to a heartbeat (default: **15**).
If you see "Daemon '\<name\>' is not responding" in the log under high
load, make this longer.

**CONTROLD_HEARTBEAT_RETRY_INTERVAL**  
Seconds until controld sends a heartbeat again that got no answer
(default: **3**).

**CONTROLD_HEARTBEAT_RETRY**  
How many heartbeats in a row may go without an answer (default: **3**).
After the last one, controld restarts the daemon.

**BACKEND_POLICY_INTERVAL**  
Seconds between two runs of the policies of an object when it is read,
for example **auto_disable** (default: **60**). The policies run when
the object is read and this time has passed since their last run, in
each process on its own. So an object can stay enabled up to this long
after its time to disable has come. A short time means more work on each
read.

# AGENT

otpme-agent runs as the user, but it reads these from this file only,
not from the config file of the user. It holds a connection to each
daemon a login session uses, for example authd or mgmtd.

**AGENT_CONNECTION_IDLE_TIMEOUT**  
Seconds after the last request on a daemon connection until otpme-agent
closes it (default: **300**). Keepalive messages do not count as
requests. The next request opens the connection again.

**AGENT_KEEPALIVE_INTERVAL**  
Seconds without a message on a daemon connection until otpme-agent sends
a keepalive message on it (default: **5**). A connection whose keepalive
message fails is closed. This is also the longest time otpme-agent waits
between two checks of its login sessions.

**AGENT_PASS_CACHE_INTERVAL**  
Seconds from one fetch of the passwords this host may keep for offline
use to the next (default: **3600**). otpme-agent also fetches them at
the first login of the user, and when one of them changes. Which
passwords a host may keep is set with the config parameter
**password_offline_cache** of a unit or site.

**AGENT_CONFIRM_ACTIONS**  
Whether otpme-agent asks to confirm each use of a YubiKey in PIV mode,
signing or decrypting, while it holds the PIN login of the card
(default: **True**). It shows what the use is for, e.g. the share or the
password. Without the PIN login it asks for the PIN instead, with the
same text.  
It asks only in a graphical session of the user: on a console the shell
reads the terminal, so the card is used without asking there.  
The user cannot switch it off.

# NETWORK

**MAX_REQUEST_SIZE**  
The largest single request OTPme accepts from the other side, in bytes
(default: **104857600**, 100 MiB). A request larger than this is
refused. This is a safety limit and not a speed setting. Raise it only
when a backup, a sync or a restore fails because something you move is
bigger than it. Most daemons have a smaller limit of their own; this
value is used where a daemon has none.

**POSIX_MSGSIZE_MAX**  
The largest message, in bytes, in the POSIX message queues the OTPme
processes talk over (default: **8192**). A longer message is sent in
parts. **auto** reads it from */proc/sys/fs/mqueue/msgsize_max*. Linux
refuses a larger value than that file for a process without the
privilege to exceed it, see **mq_overview**(7).

**RLIMIT_MSGQUEUE**  
The most bytes all POSIX message queues of a user may hold together
(default: **2621440000**), see **getrlimit**(2). Applied when an OTPme
process starts. As with **RLIMIT_NOFILE**, it is only ever raised, never
lowered, and only root can raise the hard limit. A process without
privileges takes the soft limit only as high as the hard limit allows.

**RLIMIT_NOFILE**  
The most files a process may have open (default: **65536**), see
**getrlimit**(2). Applied when an OTPme process starts.  
Set here rather than left to the system, because
*/etc/security/limits.conf* does not reach a daemon: that file is read
by **pam_limits**(8), which only runs for a PAM session - a login, an
ssh connection, su. A service started at boot never passes through it
and keeps the kernel default of 1024. With a socket per connection
across the daemons under **otpme-controld**, plus cluster, redis and the
index database, that runs out and shows up as "too many open files".  
Only ever raised, never lowered, so a higher limit set through your init
system (**LimitNOFILE** for systemd, **rc_ulimit** in
*/etc/conf.d/otpme* for OpenRC) is left alone. Only root can raise the
hard limit. A process without privileges, such as a command or the
otpme-agent of a user, takes the soft limit only as high as the hard
limit allows.

**FLOATING_IP_IFACE**  
The network interface the floating IP of the site is put on, on the
master node, e.g. **eth0** (default: not set). Without it, the interface
whose network holds the address is taken, with the netmask of that
network. With it, the address is put on this interface as a single host
(/32, or /128 for IPv6).

# STORAGE

**OBJECT_JSON_COMPRESSION**  
How the files of the objects are compressed: **lz4**, **gzip**, **zlib**
or **bzip** (default: not set, uncompressed; **none** is the same). A
file is read with whatever it was written with, so a change takes effect
with the next write of each object, and the old files stay readable. Any
other value is refused when OTPme starts.

**PRETTIFY_OBJECT_JSON**  
Write the files of the objects with line breaks and indentation, easier
to read and bigger (default: **False**).

**FSYNC_FILE_WRITES**  
Sync every file OTPme writes to disk before it goes on: objects,
transactions, keys (default: **False**).  
A file is written under another name first and then put in place of the
old one, so a crash leaves the old file or the new one, never part of
one. (Not a file with a second hard link, or one OTPme may write but not
replace: those are written in place.) On ext4 that holds without this,
and a crash loses only what was written in the last seconds. Turn it on
for another filesystem, or where those seconds must not be lost
either.  
It costs a few milliseconds on every file, and a change of one object
writes several of them. Measure it on your disks before you turn it on
for a site with many changes.

# LOGGING

**LOGLEVEL**  
The lowest level that is logged: **CRITICAL**, **ERROR**, **WARNING**,
**INFO** or **DEBUG** (default: **INFO**). Any other value is taken as
**INFO**, with a message. Debug options such as **-dd** log **DEBUG**
whatever is set here.

**LOG_AUTH_DATA**  
Print what each authentication request sends: password, OTP, SOTP,
challenge and so on (default: **False**). **True** does it for every
user, a comma separated list of user names for these users only. It
works only with **LOGLEVEL** **DEBUG** or a debug option. It prints to
the standard output of the daemon, never to the log file or syslog: in
the foreground that is the terminal, under systemd the journal. Use it
only to find a fault in a test setup, never in production.

**LOG_EXC_INFO**  
Add the traceback of the exception that is being handled to warning,
error and critical log messages (default: **False**). Only for messages
that are written while an exception is handled; where the code says
itself whether to add it, that wins.

**TRACEBACKS**  
Show the Python traceback when a command or daemon ends with an error
(default: **False**). Without it, only the error message is shown. Read
when the process starts.

**SHOW_JOB_TITLE**  
Show the name of the job in the process title of a job, after its UUID
(default: **False**).

# SSO

**SSO_SERVER**  
Run the SSO portal, **httpd**, on this host (default: **False**). Only
for hosts: a node runs it always, whatever is set here.  
The host has to be an SSO host of its site, see **add_sso_host** in
**otpme-site**(1). Only then is it synced what the portal needs:
**SSO_CERT**, **SSO_KEY**, **SSO_SECRET** and **SSO_CSRF_SECRET**.
Without that, httpd stops at start with an error that says so.

# BACKUP

## Backup server

These make this system a backup server.

**BACKUP_SERVER**  
Accept backups from other systems (default: **False**). On a node,
backupd always runs, for the backups of the node and its shares, and
this makes it listen for others as well. On a host, this starts backupd.

**BACKUP_DIR**  
The directory all repositories are kept in (default: */var/backups*). A
repository *type*/*site*/*name* is the directory *site*/*type*/*name* in
it. It has to exist.

**ALLOW_NEW_BACKUP_REPOS**  
Who may create a new repository with their first backup (default:
**False**). **False**: nobody, **True**: everyone, or a comma separated
list of the names (CN) in the client certificates that may. A repository
that exists asks for its password either way.

## Backup of this system

The backups of nodes and shares are set with config parameters of these
objects, see **otpme-backup**(1). The ones below are for the backup of a
host, or of a system that is not part of the realm. They are used by
**otpme-backup start localhost**, as root. Nothing starts it on a
schedule; run it from cron or a systemd timer.

**BACKUP_REPOSITORY**  
Where the backup goes: *server*:*type*/*site*/*name*, e.g.
**node1.berlin.example.org:host/berlin/client1** (default: not set).
*server* is the address of a backup server.

**BACKUP_MODE**  
How a new repository stores its files: **pack** or **tree** (default:
**pack**). It counts only when the repository is created; after that it
keeps its mode. See **otpme-backup**(1).

**BACKUP_REPO_PASS_FILE**  
The file with the password of the repository, in its first line
(default: */etc/otpme/backup.pass*).

**BACKUP_KEY_FILE**  
The file with the key the backup is encrypted with, as 64 hex digits in
its first line (default: */etc/otpme/backup.key*). Make one with:

**openssl rand -hex 32 \> /etc/otpme/backup.key**

Keep a copy elsewhere: without the key, nothing in the backup can be
read.

Both files are read only by root, and not at all if anyone may read
them: then OTPme says so.

**BACKUP_EXCLUDE_SPECIAL**  
Leave out special files: devices, sockets, pipes (default: **True**).

**BACKUP_EXCLUDES**  
A comma separated list of paths to leave out, relative to */* and
without the leading slash; patterns with **\*** and **?** work (default:
not set).

**BACKUP_INCLUDES**  
A comma separated list of paths, like **BACKUP_EXCLUDES**, that are
backed up even when an exclude covers them (default: not set).

**BACKUP_CLIENT_CERT**  
The client certificate of a system that is not part of the realm
(default: not set). Make it with **create_client_cert** in
**otpme-ca**(1), e.g.:

**otpme-ca create_client_cert SITE_CA client1 cert.pem key.pem**

Its CN is the name **ALLOW_NEW_BACKUP_REPOS** lists. A host of the realm
uses its own certificate and needs none of these three.

**BACKUP_CLIENT_KEY**  
The key of that certificate (default: not set).

**BACKUP_CLIENT_CA**  
The CA certificate of the site, copied from */etc/otpme/ssl/ca.pem* of a
node (default: not set).

# FILES

*/etc/otpme/otpme.conf*  
This file.

*\~/.otpme/otpme.conf*  
The config file of a user, for the parameters that say "A user can set
it" above. Any other parameter in it is ignored.

*/etc/otpme/otpme.conf.dist*  
The file as it comes with OTPme, with all parameters and a comment on
each. pip puts it in *etc/otpme/* below its *site-packages* directory,
not here; on install you copy it here, and to *otpme.conf*, see
*README.md*.

*/etc/otpme/otpme.key*, */etc/otpme/otpme.key_salt*  
The master key and its salt, see **KEY_COMMAND**.

*/etc/otpme/backup.pass*, */etc/otpme/backup.key*  
The password of the repository and the key of the backup of this system,
see **BACKUP**.

*/etc/otpme/redis.conf*, */etc/otpme/postgresql.conf*, */etc/otpme/mysql.cnf*  
If there, used instead of the config OTPme writes for Redis, PostgreSQL
or MySQL. The parameters of this file for that program then do nothing.

# SEE ALSO

**otpme**(1), **otpme**(7), **otpme-tool**(1), **otpme-site**(1),
**otpme-cluster**(1), **otpme-client**(1), **otpme-backup**(1),
**otpme-ca**(1), **otpme-pass**(1), **otpme-role**(1),
**otpme-share**(1), **otpme-shell**(1), **pam_otpme**(8)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
