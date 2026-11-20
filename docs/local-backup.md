# NAME

local-backup - work on a backup repository directly

# SYNOPSIS

**local-backup** **-d** *repository* \[**-k** *key* \| **-p**
*password_file*\] \[**-v**\] \[**--no-compress**\] *command*
\[*arguments*\]

# DESCRIPTION

**local-backup** works on a repository in a directory of this machine,
without a backup server and without a realm. It is the tool for the
backup server itself: check a repository, free space, or apply the
retention by hand. It can also back up into a directory and restore from
it, on any machine.

*repository* is the directory of the repository. On a backup server of
OTPme that is *\<BACKUP_DIR\>/\<site\>/\<type\>/\<name\>*, for example
*/var/backups/berlin/share/data*, see **otpme-backup**(1). Only
**backup** makes a repository; every other command on a directory
without one says so and changes nothing.

A command that reads or writes the files needs the key: **backup**,
**restore**, **ls** and **verify**. **-k** takes it as 64 hex
characters; for a repository of OTPme that is the **backup_key** of the
object. **-p** takes a file with a password instead, from which a key is
made; without either of them it is asked for. A repository of OTPme is
encrypted with the key, so a password does not open it. The other
commands work on the repository alone and need neither.

The commands that change the repository, and **verify**, take the lock
of the repository, the one a backup, a restore and a repack of the
backup daemon take as well.

# OPTIONS

**-d, **--backup-dir** *repository***  
The repository to work on.

**-k, **--key** *key***  
The key, 64 hex characters.

**-p, **--password-file** *file***  
A file with the password a key is made from.

**-v, **--verbose****  
Say more.

**--no-compress**  
For **backup**: store the files without compressing them first.

# COMMANDS

**backup** \[**--name** *name*\] \[**--special-files**\] \[**--exclude** *pattern*\] \[**--include** *pattern*\] \[**--mode** **tree**\|**pack**\] \[**--dry-run**\] *source*  
Back up the directory *source* into a new snapshot, named after the time
it started unless **--name** says otherwise. The patterns work as with
**otpme-backup start**. Device files, FIFOs and sockets are left out
unless **--special-files** is given. **--mode** is taken by a new
repository only (default: pack); an existing one keeps its mode.

**restore** \[**--path** *path*\] \[**--dry-run**\] *snapshot* *destination*  
Restore a snapshot into *destination*, or with **--path** only that file
or directory.

**list**  
List the snapshots, as **otpme-backup list** does.

**ls** \[**--full-path**\] \[**-R**\] *snapshot* \[*path*\]  
List what a snapshot holds, as **otpme-backup ls** does.

**verify *snapshot***  
Read every block of the snapshot and check that it is the block it
should be. The exit code is 1 when one is not.

**delete *snapshot***  
Delete the snapshot, and the blocks no other snapshot uses.

**retention** \[**--daily** *n*\] \[**--weekly** *n*\] \[**--monthly** *n*\] \[**--dry-run**\]  
Apply the retention, see **otpme-backup**(1). A number given here counts
instead of the one in *.daily*, *.weekly* or *.monthly*. **--dry-run**
names the snapshots it would delete.

**gc**  
Remove the blocks no snapshot uses. A pack file left empty is deleted,
the others keep the space until **repack**.

**repack**  
Rewrite the pack files that hold blocks nobody uses, to get the space
back.

**compact**  
Compact the databases of the repository, to get back the space deleted
entries took.

**repair**  
Remove entries of the snapshot index that no snapshot has.

**rebuild-index**  
Build the index of the pack files again from the pack files, for an
index that is lost or broken.

**jobs**  
List the jobs the backup daemon started for the repository: when, for
how long, their state and what came of them. Given **BACKUP_DIR**
instead of a repository, list those of all repositories below it. A job
that is started or running but has no process any more is shown as
**aborted**. A finished job is listed for 7 days.

**run-job *id***  
Run a job the backup daemon started. Not for use by hand.

# EXAMPLES

**local-backup -d /var/backups/berlin/share/data list**  
The snapshots of the share **data**, on its backup server.

**local-backup -d /var/backups/berlin/share/data -k *key* verify 2026-03-29T02-00-05**  
Check that snapshot block by block.

**local-backup -d /var/backups/berlin/share/data retention --daily 7 --weekly 4 --dry-run**  
Which snapshots a retention of 7 days and 4 weeks would delete.

**local-backup -d /var/backups/berlin/share/data repack**  
Get back the space of deleted snapshots.

**local-backup -d /var/backups jobs**  
The jobs of all repositories on the backup server.

# SEE ALSO

**otpme-backup**(1), **otpme.conf**(5)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2026 the2nd. License: GPLv3
