# NAME

otpme - global options for OTPme management commands

# SYNOPSIS

**otpme-*name*** \[*global options*\] *command* \[*options*\]

# DESCRIPTION

All OTPme management commands (otpme-user, otpme-token, otpme-client,
etc.) share a common set of global options described here. For a
conceptual overview of the OTPme system, see **otpme**(7).

# GLOBAL OPTIONS

## Connection Options

**-r *realm***  
Connect to a specific realm.

**-s *site***  
Connect to a specific site.

**-t *timeout***  
How long to wait until the connection to the daemon is established, in
seconds. Default: 5.

**-tt *timeout***  
How long to wait when a request is sent and for its answer, in seconds.
Default: 15. Use a higher value for commands that take long on the
server.

**--reneg-timeout *timeout***  
Only for **otpme-agent**: how long the agent waits for an answer when it
renews a login session, in seconds. Default: 30.

**-c *config_file***  
Use alternative config file.

**--no-dns**  
Do not resolve OTPme site address via DNS. This is the default, see
**USE_DNS** in **otpme.conf**(5).

**--use-dns**  
Resolve OTPme site address via DNS.

**--login-no-dns**  
Do not resolve OTPme login point via DNS.

**--login-use-dns**  
Resolve OTPme login point via DNS. This is the default, see
**LOGIN_USE_DNS** in **otpme.conf**(5).

## Authentication Options

**--use-ssh-agent **y**\|**n****  
Use ssh-agent for authentication (**y**) or not (**n**). The value is
required.

**--use-smartcard **y**\|**n****  
Use a smartcard for authentication (**y**) or not (**n**). The value is
required.

**--stdin-pass**  
Read the password, OTP or PIN from stdin.

**--auth-token *token***  
Emulate login with given token in API mode.

**-u *username***  
User used for authentication (e.g. when joining the realm as an ordinary
user rather than the local root).

**--impersonate-token *user***/***token***  
Work as the given token, for example **alice/login**. Needs admin
permissions. You can not impersonate your own token, the token of the
realm admin, or a token or user in **site_admin_blacklist**. Each use is
written to the log and the audit log. Has no effect with **--api**.

**--fetch-scripts**  
Fetch scripts from the server instead of using cached ones.

## Communication Options

**--socket**  
Send the command to mgmtd over its local Unix socket instead of the
network. This only works on a node. No login is needed: mgmtd takes the
name of the local system user and works as the OTPme user of the same
name, with that user's default token. See also **USE_MGMTD_SOCKET** in
**otpme.conf**(5).

**--api**  
Run the command in this process, directly on the local data, without a
daemon and without a login. This only works on a node, normally as root.
Use it with care while the OTPme daemons are running: changes can be
lost or break things. OTPme prints a warning in this case.

## General Options

**--type *object_type***  
Object type to act on, for example the token type. It goes before the
command, for example **otpme-token --type totp add alice/totp**.

**-f**  
Do not ask any questions: every confirmation counts as answered with
yes. This also applies to deleting objects and to signing: with **-f**,
data is signed without showing it to you first.

**--no-pager**  
Do not page command output through a pager (e.g. **less**) even when it
exceeds the terminal size. See also **USE_PAGER** in **otpme.conf**(5).

**--changelog *text***  
Add the given text as a custom entry to the object changelog written by
this command. Only meaningful for commands that change an object.

**--print-raw-sign-data**  
When you are asked to sign something (for example a job of
**otpme-deploy**(1)), show the raw data that is signed instead of the
short summary.

**--version**  
Show version.

**-v**  
Enable verbose mode.

## Debug Options

Debug options start with **-d**, followed by one or more letters. **-d**
alone is not valid. Each letter selects a topic, a letter with a digit a
sub topic (for example **-dc** for object caching, **-dc1** for cache
flushing). You can combine topics in one option, for example **-dcn**.
Some topics have levels: repeat the letter to raise the level (**-dee**,
**-dTT**).

Selecting a topic sets the log level to DEBUG, so its messages are
shown. The options that change how OTPme runs (**-dD**, **-de**,
**-dE**, **-dP**, **-dt**) do not change the log level.

**General**

**-dd**  
Enable debug output in general (log level DEBUG).

**-dD**  
Do not go to background and log to stdout.

**-dt**  
Add timestamps to debug output.

**--color-logs**  
Show log messages in color.

**-de**  
Print tracebacks.

**-dee**  
Print tracebacks and raise exceptions instead of handling them.

**-dE**  
Add exception info to warning, error, critical and fatal log messages
(sets **LOG_EXC_INFO** for this run).

**Caches**

**-dc**  
Print when objects are read from cache.

**-dc1**  
Print when caches are flushed.

**-da**  
Print when entries are added to function caches.

**-dh**  
Print function cache hits.

**Backend and files**

**-db**  
Print when objects are read from the backend.

**-dr**  
Print file reads.

**-dw**  
Print file writes.

**-dA**  
Debug transactions.

**-dA1**  
Debug reading and writing of transactions on disk.

**-dA2**  
Debug each single transaction action.

**Locks**

**-dL**  
Debug locks.

**-dL1**  
Debug waiting for locks.

**Network and protocols**

**-dn**  
Debug connections (accept, connect, close).

**-dN**  
Debug network packets.

**-dp**  
Debug protocol handling (preauth, commands).

**-dC**  
Debug client messages.

**-dC1**  
Debug client side crypto (keys, DH, signatures).

**-dH**  
Debug host authentication (certificates, challenges).

**Cluster and sync**

**-ds**  
Debug object sync.

**-dS**  
Debug cluster communication.

**Objects**

**-do**  
Debug policies.

**-dx**  
Debug object extensions.

**Processes and modules**

**-df**  
Debug forking and dropping of privileges.

**-dm**  
Print when OTPme modules are loaded.

**Profiling and timing**

**-dM**  
Trace function and method calls.

**-dP**  
Profile with cProfile.

**-dT**  
Print a warning if a function or method call takes longer than
**--debug-timing-limit**.

**-dTT**  
Print the timing result after each method finishes (instead of the
warnings of **-dT**).

**-dTTT**  
Print a warning each time a method call gets slower (instead of the
output of **-dT** and **-dTT**).

**Filters and limits**

**--log-filter *daemon1,daemon2***  
Only show log messages of the given daemons, for example
**mgmtd,syncd**.

**--debug-daemons *daemon1,daemon2***  
Only apply the debug options inside the given daemons. Commands you run
from a shell are not affected.

**--debug-users *user1,user2***  
Only trace and time calls made for requests of the given users.

**--debug-func-names *regex1,regex2***  
With **-dT**: only time the functions and methods whose full name
(*module.class.method*) matches one of the regular expressions.

**--debug-func-start *regex1,regex2***  
With **-dT**: start timing at the first call of a function or method
that matches one of the regular expressions. From then on, all calls are
timed.

**--debug-func-caches *cache1,cache2***  
With **-da** or **-dh**: only show the given function caches.

**--debug-timing-limit *seconds***  
With **-dT**: warn about calls that take longer than this. The timing
results also only show functions whose total time is longer. Default:
0.2.

**--debug-profile-sort **cumtime**\|**ncalls**\|**tottime****  
With **-dP**: how the profile output is sorted. Default: **tottime**.

**--debug-profile-print-callers *func1,func2***  
With **-dP**: also show who called the given functions.

## Job Options

**--lock-wait-timeout *seconds***  
How long to wait for an object that another job has locked. Default: 0
(do not wait, fail at once).

**--job-timeout *seconds***  
Stop the job on the server when it shows no activity for this long.
Default: 60.

## Advanced Options

**--enable-typing**  
Check on every function call that the arguments have the types the code
expects (Python type hints). This is for finding bugs and makes
everything slower.

**--disable-locking**  
Do not lock objects while changing them. This only has an effect with
**--api**, because normally mgmtd does the locking. Only use it when
nothing else changes objects at the same time: changes can get lost.

## Daemon Options

These options are used when starting the daemons with
**otpme-controld**.

**-l *file***  
Write the log to this file instead of stdout.

**--no-index-start**  
Do not start and stop the index database with the daemons.

**--no-cache-start**  
Do not start and stop the cache with the daemons.

**--cache-flush**  
Empty the cache when the daemons start.

**--ignore-changed-objects**  
hostd syncs objects even if they change while syncing.

**--keep-floating-ip**  
On the master node: do not remove the floating IP when the daemons stop.

# SEE ALSO

**otpme**(7), **otpme.conf**(5), **pam_otpme**(8),
**otpme-accessgroup**(1), **otpme-backup**(1), **otpme-ca**(1),
**otpme-client**(1), **otpme-deploy**(1), **otpme-device**(1),
**otpme-dictionary**(1), **otpme-group**(1), **otpme-host**(1),
**otpme-inventory**(1), **otpme-node**(1), **otpme-policy**(1),
**otpme-pool**(1), **otpme-realm**(1), **otpme-resolver**(1),
**otpme-role**(1), **otpme-script**(1), **otpme-share**(1),
**otpme-site**(1), **otpme-token**(1), **otpme-tool**(1),
**otpme-trash**(1), **otpme-unit**(1), **otpme-user**(1),
**otpme-vlan**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2026 the2nd. License: GPLv3
