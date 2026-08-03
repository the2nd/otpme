# NAME

otpme-share - manage OTPme file shares

# SYNOPSIS

**otpme-share** *command* \[*options*\] \[*share*\]

# DESCRIPTION

**otpme-share** manages file shares in the OTPme system. A share
provides access to a directory tree and can optionally be encrypted.

Shares support two types of scripts: An **add script** (default:
add_share.sh) is automatically executed when a share is created to set
up the share directory structure. A **mount script** (default:
mount_share.sh) can be configured to run each time a user mounts the
share. Scripts are executed as the OTPme system user and group. The
default scripts for new shares can be configured via the
**default_share_add_script** and **default_share_mount_script** config
parameters at site or unit level.

# HOME SHARES

A normal share hands out its root directory to everybody. A **home
share** hands out *share_root***/***home_dir* instead, so every user
gets their own directory and sees nothing else. The directory is created
on the first mount, owned by the user and by default with mode 0700 (see
**home_share_permissions**).

Two naming schemes are available, chosen when the share is created:

> **--home-share**  
> The directory is named after the user UUID. Renaming a user keeps the
> directory.
>
> **--home-share-uid**  
> The directory is named after the user name (uid), which is what one
> expects below e.g. /home. Implies **--home-share**.

A **root mount token** gets no home dir and mounts *share_root* itself,
so it reaches the home dirs of all users (see **add_root_mount_token**).

Home shares can be encrypted. Every home dir is then encrypted on its
own, with a share key per user, which is why an encrypted home share has
no root mount token.

# COMMANDS

## Share Management

**add \[**--home-share**\] \[**--home-share-uid**\] \[**--force-group** *group*\] \[**--force-directory-mode** *mode*\] \[**--force-create-mode** *mode*\] \[**--crypt**\] \[**--no-key-gen**\] \[**--block-size** *size*\] \[**--key-len** *len*\] \[**--restore** *restore_share*\] \[**--restore-token** *token*\] *share***  
Create a new share. Use **--force-group** to set forced group,
**--force-directory-mode** and **--force-create-mode** to set
permissions for new directories and files. Use **--crypt** to enable
encryption, **--restore** to add a restore share and **--restore-token**
for encrypted restore shares.

**--home-share**  
Create a home share (see **HOME SHARES** above). Each user gets their
own subdirectory, named after the user UUID.

**--home-share-uid**  
Create a home share whose subdirectories are named after the user name
(uid) instead of the user UUID. Implies **--home-share**.

**del \[**--share-notify**\|**--no-share-notify**\] \[**--persist-mount**\|**--no-persist-mount**\] *share***  
Delete a share. Asks for confirmation according to the confirmation
policy, and warns about assigned tokens and roles. For an encrypted
share it also warns that the share keys are deleted with it, so its data
can then only be decrypted by someone in possession of the master
password. Online hosts are told to unmount the share.

**--share-notify**  
Send unmount notification to all online hosts.

**--no-share-notify**  
Do not send unmount notification to all online hosts.

**--persist-mount**  
Also remove persisted share mounts on hosts.

**--no-persist-mount**  
Keep persisted share mounts on hosts (transient unmount only).

**show \[*share*\]**  
Display share information.

**list \[*regex*\]**  
List shares, optionally filtered by regex pattern.

**enable \[**--share-notify**\|**--no-share-notify**\] \[**--persist-mount**\|**--no-persist-mount**\] *share***  
Enable a disabled share.

**--share-notify**  
Send notification to all online hosts on new share permissions.

**--no-share-notify**  
Do not send notification to all online hosts on new share permissions.

**--persist-mount**  
Persist new share mounts on hosts.

**--no-persist-mount**  
Do not persist new share mounts on hosts.

**disable \[**--share-notify**\|**--no-share-notify**\] \[**--persist-mount**\|**--no-persist-mount**\] *share***  
Disable a share without deleting it.

**--share-notify**  
Send notification to all online hosts on revoked share permissions.

**--no-share-notify**  
Do not send notification to all online hosts on revoked share
permissions.

**--persist-mount**  
Also remove persisted share mounts on hosts.

**--no-persist-mount**  
Keep persisted share mounts on hosts (transient unmount only).

**rename *share* *new_name***  
Rename a share.

**move \[**--keep-acls**\] *share* *unit***  
Move share to a different unit.

**touch *share***  
Re-index the object to fix potential index problems.

## Share Configuration

**root_dir *share* *path***  
Set the share root directory.

**force_group *share* *group***  
Files and directories will always be owned by the given group.

**force_create_mode *share* *mode***  
Set file creation mode.

**force_directory_mode *share* *mode***  
Set directory creation mode.

**home_share_permissions *share* *mode***  
Mode the per user directories of a home share are created with, in
python format (e.g. **0o750**). The default **0o700** keeps the users
out of each others home dirs.

**enable_ro *share***  
Make share read-only.

**disable_ro *share***  
Make share read-write.

**description *share* \[*description*\]**  
Set share description.

**info \[**--language** *LANG*\] *share* \[*info*\]**  
Set free-form info text. If *info* is omitted, the current info text is
opened in the editor specified by the **EDITOR** environment variable.

**dump_info \[**--language** *LANG*\] *share***  
Dump the info text to stdout.

## Mount Script

A mount script is executed each time the share is mounted by a user. It
can be used to perform custom actions during mount, such as preparing
the share directory or checking prerequisites. The mount script must be
enabled separately after being configured.

**mount_script *share* *mount_script* \[**--** *script_options*\]**  
Change share mount script.

**enable_mount_script *share***  
Enable share mount script.

**disable_mount_script *share***  
Disable share mount script.

## Encryption

**get_share_key *share* *user***  
Get encrypted share key for a user.

## Token and Role Management

**add_token *share* *token_path***  
Add a token to the share.

**remove_token *share* *token_path***  
Remove a token from the share.

**list_tokens *share***  
List tokens assigned to the share.

**add_role *share* *role***  
Add a role to the share.

**remove_role *share* *role***  
Remove a role from the share.

**list_roles \[**-r**\] *share***  
List roles assigned to the share. Use **-r** for recursive listing.

**list_users *share***  
List users of the share.

## Host Management

**add_host \[**--share-notify**\|**--no-share-notify**\] \[**--persist-mount**\|**--no-persist-mount**\] *share* *host***  
Add a host to the share.

**--share-notify**  
Send notification to all online hosts on new share permissions.

**--no-share-notify**  
Do not send notification to all online hosts on new share permissions.

**--persist-mount**  
Persist new share mounts on hosts.

**--no-persist-mount**  
Do not persist new share mounts on hosts.

**remove_host \[**--share-notify**\|**--no-share-notify**\] \[**--persist-mount**\|**--no-persist-mount**\] *share* *host***  
Remove a host from the share.

**--share-notify**  
Send notification to all online hosts on revoked share permissions.

**--no-share-notify**  
Do not send notification to all online hosts on revoked share
permissions.

**--persist-mount**  
Also remove persisted share mounts on hosts.

**--no-persist-mount**  
Keep persisted share mounts on hosts (transient unmount only).

**list_hosts *share***  
List hosts assigned to the share.

**limit_hosts \[**--share-notify**\|**--no-share-notify**\] \[**--persist-mount**\|**--no-persist-mount**\] *share***  
Limit share access to assigned hosts and host groups.

**--share-notify**  
Send notification to all online hosts on revoked share permissions.

**--no-share-notify**  
Do not send notification to all online hosts on revoked share
permissions.

**--persist-mount**  
Also remove persisted share mounts on hosts.

**--no-persist-mount**  
Keep persisted share mounts on hosts (transient unmount only).

**unlimit_hosts \[**--share-notify**\|**--no-share-notify**\] \[**--persist-mount**\|**--no-persist-mount**\] *share***  
Remove host-based access limitation on the share.

**--share-notify**  
Send notification to all online hosts on new share permissions.

**--no-share-notify**  
Do not send notification to all online hosts on new share permissions.

**--persist-mount**  
Persist new share mounts on hosts.

**--no-persist-mount**  
Do not persist new share mounts on hosts.

## Master Password Token

**add_master_password_token *share* *token_path***  
Allow a token to mount the share with master password.

**remove_master_password_token *share* *token_path***  
Remove a master password token from the share.

## Root Mount Token

A root mount token gets no home dir, it mounts *share_root* itself and
thus reaches the home dirs of all users (see **HOME SHARES** above).
Only available for unencrypted home shares.

**add_root_mount_token \[**--share-notify**\|**--no-share-notify**\] \[**--persist-mount**\|**--no-persist-mount**\] *share* *token_path***  
Let a token mount the share root of a home share. The share root the
token gets changes, so the token is told to mount again, like with
**add_token**.

**remove_root_mount_token \[**--share-notify**\|**--no-share-notify**\] \[**--persist-mount**\|**--no-persist-mount**\] *share* *token_path***  
Remove a root mount token from the share. The token is told to unmount,
like with **remove_token**.

## Pool and Node Management

**add_pool *share* *pool***  
Add a pool to the share.

**remove_pool *share* *pool***  
Remove a pool from the share.

**list_pools *share***  
List pools assigned to the share.

**add_node *share* *node***  
Add a node to the share.

**remove_node *share* *node***  
Remove a node from the share.

**list_nodes *share***  
List nodes assigned to the share.

## Policy Management

**add_policy *share* *policy***  
Attach a policy to the share.

**remove_policy *share* *policy***  
Remove a policy from the share.

**list_policies *share***  
List policies attached to the share.

## ACL Management

**add_acl *share* *owner_type* *owner* *acl***  
Add an access control entry.

**del_acl *share* *acl***  
Remove an access control entry.

**show_acls *share***  
Display all ACLs for the share.

**enable_acl_inheritance *share***  
Enable ACL inheritance from parent objects.

**disable_acl_inheritance *share***  
Disable ACL inheritance.

## Import/Export

**export \[**--password** *PASS*\] *share***  
Export share configuration.

**remove_orphans *share***  
Remove orphaned object references.

# OPTIONS

## Creation Options

**--force-group *GROUP***  
Force group for the share.

**--force-directory-mode *MODE***  
Force directory creation mode.

**--force-create-mode *MODE***  
Force file creation mode.

**--crypt**  
Enable encryption for the share.

**--no-key-gen**  
Do not generate an AES key.

**--block-size *SIZE***  
Encrypted share block size (default 4096).

**--key-len *LENGTH***  
AES key length.

**--restore *RESTORE_SHARE***  
Add restore share.

**--restore-token *TOKEN***  
Add token restore share.

## Display Options

**-a**  
Show all shares.

**-z *SIZE***  
Limit output size.

**--fields *FIELD1,FIELD2***  
Display only specified fields.

**--node-limit *N***  
Limit number of nodes shown.

**--pool-limit *N***  
Limit number of pools shown.

**--token-limit *N***  
Limit number of tokens shown.

**--role-limit *N***  
Limit number of roles shown.

**--group-limit *N***  
Limit number of groups shown.

**--policy-limit *N***  
Limit number of policies shown.

**--limit *N***  
Limit number of items shown per object.

**--sort-by *FIELD***  
Sort output by field.

**--reverse**  
Reverse sort order.

**--raw**  
Output without headers/borders.

**--csv**  
Output as CSV.

**--csv-sep *SEP***  
CSV separator character.

**--attribute *ATTR***  
Display specific attribute in list command.

## General Options

**--keep-acls**  
Preserve ACLs when moving share.

**--password *PASS***  
Password for encrypting exports.

**-r**  
List roles recursively.

Global options are available for all commands. See **otpme**(1) for
details.

# CONFIG PARAMETERS

Configuration parameters can be set with the **config** command and
displayed with **show_config**. For a complete description of all
available parameters and their applicable object types, see
**otpme**(7).

# EXAMPLES

**otpme-share add myshare**  
Create a share

**otpme-share add --crypt secureshare**  
Create an encrypted share

**otpme-share add_token myshare alice/totp**  
Add a token to the share

**otpme-share add_pool myshare europe**  
Add a pool to the share

**otpme-share add --home-share-uid homes**  
Create a home share, each user gets *\<share_root\>/\<username\>*

**otpme-share home_share_permissions homes 0o750**  
Let the home dirs group be readable

**otpme-share add_root_mount_token homes backup/login**  
Let the token "backup/login" mount the share root and reach all home
dirs

# SEE ALSO

**otpme**(1), **otpme**(7), **otpme-pool**(1), **otpme-token**(1),
**otpme-role**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
