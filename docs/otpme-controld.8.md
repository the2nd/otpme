# NAME

otpme-controld - start, stop and watch the OTPme daemons

# SYNOPSIS

**otpme-controld** \[*options*\] **start**  
**otpme-controld** \[*options*\] **stop** \[**--timeout** *seconds*\]
\[**-k**\]  
**otpme-controld** \[*options*\] **restart** \| **reload**
\[*daemon*\]  
**otpme-controld** **status**

# DESCRIPTION

**otpme-controld** runs the OTPme daemons of this node or host. It runs
as root. It starts the other daemons as the OTPme user, except
**confd**, which keeps root. See **ARCHITECTURE OVERVIEW** in
**otpme**(7) for what each daemon does.

On a node it starts, in this order: **hostd**, **mgmtd**, **joind**,
**scriptd**, **syncd**, **authd**, **ssod**, **clusterd**, **httpd**,
**fsd**, **backupd** and **confd**. **clusterd** starts **ldapd**,
**idled** and **racd** when the cluster is ready, and controld watches
them from then on. On a host it starts **hostd** and **confd**, plus
**httpd** with **SSO_SERVER** and **backupd** with **BACKUP_SERVER**,
see **otpme.conf**(5).

Before the daemons it starts the index database and the cache server,
see **AUTOSTART_INDEX** and **AUTOSTART_CACHE** in **otpme.conf**(5). On
the master node it also holds the floating IP of the site, and starts
FreeRADIUS and haproxy where they are enabled.

controld checks its daemons every **CONTROLD_HEARTBEAT_INTERVAL**
seconds. It starts a daemon that is not running, and restarts one that
does not answer, see **DAEMON** in **otpme.conf**(5).

Only root can use it. The host has to be a member of a realm, see
**otpme-tool**(1).

# COMMANDS

**start**  
Start controld and its daemons, in the background. It says "Already
running." if controld runs already. The command returns before the
daemons are up; the log shows when they are.  
With **-dD** controld stays in the foreground, see **OPTIONS**.

**stop** \[**--timeout** *seconds*\] \[**-k**\]  
Stop controld. It stops its daemons in the reverse order, removes the
floating IP, and stops the cache and the index database it started.  
A daemon gets 30 seconds to quit, then it is killed. The command waits
**--timeout** seconds for all of this (default: **60**) and fails if
controld still runs then. controld goes on stopping.  
With **-k** the command waits half the timeout and then kills controld
and all its daemons.

**restart \[*daemon*\]**  
Without a daemon: stop and start controld and all daemons. If controld
still runs after 70 seconds, it is killed.  
With a daemon: controld stops that daemon and starts it again. A daemon
reads most settings when it starts, for example **authd_workers**, see
**Daemon Tuning** in **otpme**(7). **clusterd** is not restarted on the
master node; the log says so.

**reload \[*daemon*\]**  
Without a daemon: controld reads **otpme.conf**(5) again and tells every
daemon to do the same. This is the same as sending SIGHUP to controld. A
daemon that is new on the list, for example httpd after **SSO_SERVER**
was set on a host, is started at the next heartbeat. One that is no
longer on the list is stopped.  
With a daemon: only that daemon reloads.  
A daemon that cannot reload is restarted. So is one that does not answer
within 15 seconds.

With a daemon, **restart** and **reload** fail if controld does not run
or if there is no daemon of that name.

**status**  
Print "Running." or "Stopped.". It says nothing about the single
daemons. The exit code is 0 while controld runs and 1 when it is
stopped, so a script can ask.

# OPTIONS

The options go before the command.

**--timeout** *seconds*  
For **stop**: how long to wait (default: **60**).

**-k**  
For **stop**: kill what has not quit after half the timeout.

**-l** *file*  
Write the log of controld and of all daemons to this file. Without it
every daemon writes its own file in **LOG_DIR**, or the log goes to a
syslog server, see **SYSLOG** in **otpme.conf**(5).

**--no-index-start**  
Do not start and stop the index database. It has to run already, or
controld does not start.

**--no-cache-start**  
Do not start and stop the cache server. It has to run already, or
controld does not start.

**--cache-flush**  
Empty the cache when controld starts. This is the default, see
**FLUSH_CACHE_ON_START** in **otpme.conf**(5).

**--ignore-changed-objects**  
hostd syncs objects even if they change while it syncs.

**--keep-floating-ip**  
On the master node: do not remove the floating IP when controld stops.

**-dD**  
Stay in the foreground. Add **-dd** to see the log on the terminal, and
more **-d** options to see more. Ctrl+C stops controld and its daemons.
See **otpme**(1) for all debug options, and for **--color-logs**,
**--log-filter** and **--debug-daemons**.

# SIGNALS

**SIGTERM**  
Stop, as **stop** does.

**SIGINT**  
The same. This is Ctrl+C in the foreground.

**SIGHUP**  
Reload, as **reload** without a daemon does.

controld ignores all three while it starts its daemons.

# EXAMPLES

**otpme-controld start**  
Start everything in the background.

**otpme-controld -dD -dd start**  
Start in the foreground and show the log.

**otpme-controld -dD -dd --log-filter authd,mgmtd start**  
The same, but show only the log of authd and mgmtd.

**otpme-controld reload httpd**  
Let httpd read its configuration again, for example after the SSO
certificate changed.

**otpme-controld restart authd**  
Restart authd, for example after **authd_workers** was changed.

**otpme-controld stop --timeout 120 -k**  
Stop, and kill what still runs after 60 seconds.

# FILES

*/var/run/otpme/pidfiles/otpme-controld.pid*  
The PID of controld. The directory is **RUN_DIR**, see
**otpme.conf**(5).

*/var/log/otpme/otpme-daemon.log*  
The log of each daemon, without **-l** and without **-dD**. The
directory is **LOG_DIR**.

*deploy/systemd/otpme.service*  
A systemd unit that runs **otpme-controld start**, **stop** and
**reload**.

# SEE ALSO

**otpme**(1), **otpme**(7), **otpme.conf**(5), **otpme-cluster**(1),
**otpme-tool**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
