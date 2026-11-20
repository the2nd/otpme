# NAME

otpme-backup - back up nodes, shares and hosts, and restore from their
backups

# SYNOPSIS

**otpme-backup** *command* \[*options*\] \[*backup_object*\]

# DESCRIPTION

**otpme-backup** backs up a node, a share or this host into a repository
on a backup server, lists and browses its snapshots, and restores from
them.

A backup is encrypted before it leaves the machine, with **backup_key**,
the names of the files as well. The backup server keeps what it gets,
and only once: a block that is in the repository already is not stored
again. So every snapshot is a whole backup, and the space it takes is
what changed.

The backup server is a node or a host with **BACKUP_SERVER**, see
**otpme.conf**(5). It keeps a repository per object in **BACKUP_DIR**,
and asks for its password, **backup_repo_password**.

The backup daemon starts the backups of nodes and shares by itself,
within **backup_time** and no sooner than **backup_interval** after the
last one: a node backs itself up, and the shares of a site are backed up
by its master node. It applies the retention after each of them, and
sends the report mail, see **CONFIG PARAMETERS**. A host is backed up
only with **otpme-backup start localhost**.

Which snapshots the retention keeps say the files *.daily*, *.weekly*
and *.monthly* in the repository on the backup server, each with a
number in it. The days, weeks and months are counted on the calendar,
back from today. A day without a backup counts as well.

> -   *.daily*: every snapshot of the last that many days, today
>     included.
>
> -   *.weekly*: the newest snapshot of each week, for that many weeks
>     before the daily ones.
>
> -   *.monthly*: the newest snapshot of each month, for that many
>     months before the weekly ones.

A week that has daily snapshots gets no weekly one, and a month that has
a weekly one gets no monthly one. All other snapshots are deleted.
Without any of the files nothing is deleted. The retention never deletes
a snapshot whose backup did not finish; delete it with **local-backup
delete**, see **local-backup**(1).

The backup server applies the retention as a job of its own: deleting
snapshots and getting their space back can take hours, and the backup
does not wait for it. The job goes on when OTPme is stopped or restarted
on the backup server. While it runs, a backup of the same object finds
the repository locked and is tried again later. What the job deletes is
in *backup-jobs.log* in the log directory of the backup server, and
**local-backup jobs** lists the jobs, see **local-backup**(1).

A share backed up as **tree** can be mounted as a restore share, see
**otpme-share**(1).

# COMMANDS

Every command has to be run as root. There is no ACL: what opens a
repository is its password and its key, from the config parameters of
the backup object, see **CONFIG PARAMETERS**.

*backup_object* is one of:

> **localhost**  
> This host, with what **BACKUP_REPOSITORY** and the other
> **BACKUP\_\*** settings in *otpme.conf* say, see **otpme.conf**(5).
>
> **node:*name***  
> A node, backed up from */*. Only on that node itself.
>
> **share:*name***  
> A share of this site, backed up from its root directory. A restore
> share cannot be backed up.

**start** \[**--dry-run**\] \[**--skip-special**\] \[**--exclude** *pattern*\] \[**--include** *pattern*\] \[**--apply-retention**\] *backup_object*  
Back up the object now, into a new snapshot named after the time it
started, for example **2026-03-29T02-00-00**. With **backup_enabled**
off it is refused; the global option **-f** starts it all the same. Only
one backup of a repository runs at a time, a second one says **Already
running.**

**--exclude** and **--include** take a pattern with wildcards, as often
as you like, and replace **backup_excludes** and **backup_includes** for
this backup. A pattern is matched against the path below what is backed
up, so **/var/cache** and **var/cache** are the same. An include wins
over an exclude. A directory with a file *.nobackup* in it is left
out.  
**--skip-special** leaves out device files, FIFOs and sockets; without
it **backup_exclude_special** decides.  
**--apply-retention** lets the backup server delete the snapshots its
retention no longer keeps, after the backup. A backup started by the
schedule always does. The backup server starts a job for that, and the
backup does not wait for it.  
**--dry-run** shows what would be backed up and stores nothing.

**restore** \[**--dry-run**\] \[**--snapshot** *snapshot*\] \[**--path** *path*\] **--destination** *directory* *backup_object*  
Restore a snapshot into *directory* on this machine. Without
**--snapshot** it is the newest one. **--path** restores only that file
or directory, as a path below what was backed up; **/etc/otpme** and
**etc/otpme** are the same. **--dry-run** shows what would be restored
and writes nothing.

**list *backup_object***  
List the snapshots of the object: their name, the number of files, the
data and what was stored for it, when they ran and how long, and whether
they are complete.

**ls** \[**--full-path**\] \[**--recursive**\] *backup_object* *snapshot* \[*path*\]  
List what a snapshot holds below *path*, or below what was backed up;
**/etc** and **etc** are the same. Without **--recursive** only what is
directly in it. **--full-path** shows each entry with its whole path.

**status**  
List the backups running on this machine, with the time each one
started.

# OPTIONS

Every option belongs to one command and is described with that command
above.

Global options work with every command, see **otpme**(1).

# CONFIG PARAMETERS

Set them with **config** of the site, a unit, the node or the share, for
example **otpme-share config data backup_enabled true**. A value is
looked up on the node or share, then on its unit and the units above it,
then on the site; the first one found counts. For **localhost** the
**BACKUP\_\*** settings of *otpme.conf* take their place, see
**otpme.conf**(5). The full descriptions are in **otpme**(7).

What to back up and where to:

**backup_enabled (bool)**  
Whether the object is backed up at all; without it **start** is refused
and no backup is scheduled.

**backup_server (str)**  
The node or host that keeps the backups, set by name.

**backup_key (str)**  
The AES key the backups are encrypted with, 64 hex characters. Set it
without a value, and OTPme makes one from 32 random bytes. It is kept
encrypted with the key of the site. Lose it, and the backups cannot be
read any more. Set on the site or a unit, it is the key of every object
below that has none of its own.

**backup_repo_password (str)**  
The password the backup server asks for.

**backup_mode (str)**  
**pack** or **tree**; unset a share is backed up as **tree**, which a
restore share needs, and a node as **pack**. Object types: node, share.

**backup_excludes**, **backup_includes** (list)  
The patterns **start** uses when it gets no **--exclude** or
**--include**, see there. Object types: node, share.

**backup_exclude_special (bool)**  
Whether device files, FIFOs and sockets are left out, when **start**
gets no **--skip-special**.

When the backup daemon starts a backup by itself. **otpme-backup start**
does not look at these:

**backup_time (str)**  
The time of day a backup may start, as *HH:MM-HH:MM*, for example
**02:00-03:00**; it may span midnight. Without it no backup is
scheduled.

**backup_interval (time)**  
How long after the last backup the next one may start, for example
**1D** (default: 23h).

**backup_retry_interval** (time, default: 5m), **backup_retry_count** (int, default: 12)  
How long and how often a backup waits when another backup, a restore or
a repack holds the repository.

**backup_script (str)**  
The OTPme script run before and after a scheduled backup, see
**otpme**(7).

**backup_pre_script_fail (str, default: report)**  
What a failed pre hook of **backup_script** does: **abort** starts no
backup and reports it as failed, **report** backs up all the same and
puts the failure into the log and into the report mail.

**backup_report_enabled**, **backup_report_mode**, **backup_report_mail_from**, **backup_report_mail_to**  
Whether, which and to whom a mail is sent about a scheduled backup, over
the **smtp_relay\_\*** parameters.

Each of them applies to the site, units, nodes and shares, where it does
not say otherwise.

# EXAMPLES

## Backing up a share every night

**otpme-share config data backup_server node2**  
The node **node2** keeps the backups of the share **data**.

**otpme-share config data backup_repo_password 'a long secret'**  
The password **node2** asks for. The first backup creates the repository
there with it, where **node2** allows new repositories
(**ALLOW_NEW_BACKUP_REPOS**, see **otpme.conf**(5)).

**otpme-share config data backup_key**  
Let OTPme make the key the backups of the share are encrypted with.

**otpme-share config data backup_time 02:00-03:00**  
A backup may start between 2 and 3 at night.

**otpme-share config data backup_enabled True**  
From now on the master node of the site backs it up every night.

## By hand

**otpme-backup start --dry-run share:data**  
Show what would be backed up.

**otpme-backup start --apply-retention share:data**  
Back the share up now, and let the backup server delete the snapshots
its retention no longer keeps.

**otpme-backup start --exclude /var/cache --exclude '/home/\*/.cache' node:node1**  
Back up **node1** without those directories; run it on **node1**.

**otpme-backup status**  
Show which backups are running on this machine.

## Looking into it

**otpme-backup list share:data**  
List the snapshots of the share.

**otpme-backup ls share:data 2026-03-29T02-00-05 projects**  
List what was directly in **projects** in that snapshot.

**otpme-backup ls --recursive --full-path node:node1 2026-03-29T02-00-05 /etc/otpme**  
List all of */etc/otpme*, each entry with its whole path.

## Restoring

**otpme-backup restore --destination /tmp/restore share:data**  
Restore the newest snapshot of the share into */tmp/restore*.

**otpme-backup restore --snapshot 2026-03-29T02-00-05 --path /etc/otpme --destination /tmp/restore node:node1**  
Restore only */etc/otpme* of that snapshot; what was in it ends up
directly in */tmp/restore*.

**otpme-backup restore --dry-run --destination /tmp/restore node:node1**  
Show what a restore of the newest snapshot would write.

# FILES

*/var/backups/*  
**BACKUP_DIR** on the backup server. A repository is the directory
*\<site\>/\<type\>/\<name\>/* in it, for example *berlin/share/data/*,
with its password in *.password*, the retention in *.daily*, *.weekly*
and *.monthly*, and its jobs in *jobs/*.

*/var/log/otpme/backup-jobs.log*  
What the jobs of the backup server did: the snapshots they deleted, the
space the repack got back, errors.

# SEE ALSO

**otpme**(1), **otpme**(7), **otpme.conf**(5), **otpme-node**(1),
**otpme-share**(1), **otpme-site**(1), **otpme-unit**(1),
**otpme-script**(1), **local-backup**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
