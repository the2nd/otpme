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

# COMMANDS

## Share Management

**add \[**--force-group** *group*\] \[**--crypt**\] \[**--no-key-gen**\] \[**--block-size** *size*\] \[**--key-len** *len*\] *share***  
Create a new share. Use **--crypt** to enable encryption,
**--force-group** to set forced group.

**del *share***  
Delete a share.

**show \[*share*\]**  
Display share information.

**list \[*regex*\]**  
List shares, optionally filtered by regex pattern.

**enable *share***  
Enable a disabled share.

**disable *share***  
Disable a share without deleting it.

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

**enable_ro *share***  
Make share read-only.

**disable_ro *share***  
Make share read-write.

**description *share* \[*description*\]**  
Set share description.

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

## Master Password Token

**add_master_password_token *share* *token_path***  
Allow a token to mount the share with master password.

**remove_master_password_token *share* *token_path***  
Remove a master password token from the share.

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

**--crypt**  
Enable encryption for the share.

**--no-key-gen**  
Do not generate an AES key.

**--block-size *SIZE***  
Encrypted share block size (default 4096).

**--key-len *LENGTH***  
AES key length.

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

# SEE ALSO

**otpme**(1), **otpme**(7), **otpme-pool**(1), **otpme-token**(1),
**otpme-role**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
