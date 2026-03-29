# NAME

otpme-backup - manage OTPme backups

# SYNOPSIS

**otpme-backup** *command* \[*options*\]

# DESCRIPTION

**otpme-backup** manages OTPme backups. It can start backups, list
snapshots, browse snapshot contents and restore files or entire
snapshots from a backup repository.

The *backup_object* argument identifies what to back up or restore using
the format *type*:*name* (e.g. **node:node1**, **share:data**).

# COMMANDS

**start \[**--dry-run**\] \[**--skip-special**\] \[**--exclude** *path*\] \[**--include** *path*\] \[**--apply-retention**\] *backup_object***  
Start backup for the given backup object.

**restore \[**--dry-run**\] **--snapshot** *snapshot* \[**--path** *path*\] **--destination** *destination_dir* *backup_object***  
Restore from backup repository.

**list *backup_object***  
List backup snapshots.

**ls \[**--full-path**\] \[**--recursive**\] *backup_object* *snapshot* \[*path*\]**  
List contents of a backup snapshot.

# OPTIONS

## Start Options

**--dry-run**  
Just print what would be backed up without actually performing the
backup.

**--skip-special**  
Skip special files (device files etc.).

**--exclude *path***  
Exclude *path* from backup. Can be specified multiple times.

**--include *path***  
Include *path* in backup. Can be specified multiple times.

**--apply-retention**  
Instruct the server to apply backup retention.

## Restore Options

**--dry-run**  
Just print what would be restored without actually restoring.

**--snapshot *snapshot***  
Snapshot to restore from (required).

**--path *path***  
Restore only the given path from the snapshot.

**--destination *destination_dir***  
Restore to the given destination directory (required).

## List Options

**--full-path**  
Output full path in listing.

**--recursive**  
List contents recursively.

Global options are available for all commands. See **otpme**(1) for
details.

# CONFIG PARAMETERS

Backup behaviour is controlled by configuration parameters set with the
**config** command on the backup object (node, share) or inherited from
the parent site or unit.

**backup_enabled (bool)**  
Enable or disable backups for this object.  
Object types: site, unit, node, share

**backup_exclude_special (bool)**  
Exclude special files from backup.  
Object types: site, unit, node, share

**backup_server (str)**  
Name of the node or host to use as backup server.  
Object types: site, unit, node, share

**backup_time (str)**  
Backup time window in HH:MM-HH:MM format (e.g. "02:00-03:00").  
Object types: site, unit, node, share

**backup_interval (int)**  
Backup interval (accepts human-readable time values, e.g. 1h, 1D).  
Object types: site, unit, node, share

**backup_key (str)**  
AES key (64-character hex string) for encrypting backups. Automatically
generated if not set.  
Object types: site, unit, node, share

**backup_repo_password (str)**  
Password for authenticating to the backup server.  
Object types: site, unit, node, share

**backup_mode (str)**  
Backup mode. Valid values: **pack**, **tree**.  
Object types: node, share

**backup_excludes (list)**  
Comma-separated list of patterns to exclude from backup.  
Object types: node, share

**backup_includes (list)**  
Comma-separated list of patterns to include in backup.  
Object types: node, share

For a complete description of all available parameters see **otpme**(7).

# EXAMPLES

**otpme-backup start node:node1**  
Start a backup for node **node1**.

**otpme-backup start --dry-run --skip-special node:node1**  
Show what would be backed up, skipping special files.

**otpme-backup start share:data**  
Start a backup for share **data**.

**otpme-backup list node:node1**  
List all backup snapshots for node **node1**.

**otpme-backup ls node:node1 2026-03-29T02:00:00 /etc**  
List contents of **/etc** in the given snapshot.

**otpme-backup restore --snapshot 2026-03-29T02:00:00 --destination /tmp/restore node:node1**  
Restore snapshot of node **node1** to **/tmp/restore**.

**otpme-backup restore --snapshot 2026-03-29T02:00:00 --path /etc/otpme --destination /tmp/restore node:node1**  
Restore only **/etc/otpme** from a specific snapshot.

**otpme-backup restore --snapshot 2026-03-29T02:00:00 --destination /tmp/restore share:data**  
Restore share **data** to **/tmp/restore**.

# SEE ALSO

**otpme**(1), **otpme-tool**(1), **otpme**(7)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
