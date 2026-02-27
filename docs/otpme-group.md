# NAME

otpme-group - manage OTPme groups

# SYNOPSIS

**otpme-group** *command* \[*options*\] \[*group*\]

# DESCRIPTION

**otpme-group** manages POSIX/LDAP groups in the OTPme system. Groups
have a GID number and can contain users, tokens, and roles. Each user
has a default group, and groups are exposed via LDAP with standard
attributes.

# COMMANDS

## Group Management

**add \[**--attributes** *attr1=val1,attr2=val2*\] *group***  
Create a new group, optionally with LDIF attributes.

**del *group***  
Delete a group.

**show \[*group*\]**  
Display group information. Without arguments, shows all groups.

**list \[*regex*\]**  
List groups, optionally filtered by regex pattern.

**enable *group***  
Enable a disabled group.

**disable *group***  
Disable a group without deleting it.

**rename *group* *new_name***  
Rename a group.

**move \[**--keep-acls**\] *group* *unit***  
Move group to a different unit.

**touch *group***  
Re-index the object to fix potential index problems.

## Token and Role Assignment

**add_token \[**--no-auto-sign**\] \[**--sign** **--tags** *tag1,tag2*\] *group* *token_path***  
Add a token to the group.

**remove_token \[**--keep-sign**\] *group* *token_path***  
Remove a token from the group.

**list_tokens *group***  
List tokens assigned to the group.

**add_role *group* *role***  
Add a role to the group.

**remove_role *group* *role***  
Remove a role from the group.

**list_roles *group***  
List roles assigned to the group.

## User Management

**list_users *group***  
List users in the group.

**list_default_group_users *group***  
List users that have this group as their default group.

## Sync User Management

**add_sync_user *group* *user***  
Add a sync user to the group.

**remove_sync_user *group* *user***  
Remove a sync user from the group.

**list_sync_users *group***  
List sync users in the group.

## Policy Management

**add_policy *group* *policy***  
Attach a policy to the group.

**remove_policy *group* *policy***  
Remove a policy from the group.

**list_policies *group***  
List policies attached to the group.

## ACL Management

**add_acl *group* *owner_type* *owner* *acl***  
Add an access control entry.

**del_acl *group* *acl***  
Remove an access control entry.

**show_acls *group***  
Display all ACLs for the group.

**enable_acl_inheritance *group***  
Enable ACL inheritance from parent objects.

**disable_acl_inheritance *group***  
Disable ACL inheritance.

## Configuration and Attributes

**config \[**-d**\] *group* *parameter* \[*value*\]**  
Set or display a configuration parameter. Use **-d** to delete (reset to
default).

**show_config *group* \[*parameter*\]**  
Show all configuration parameters.

**description *group* \[*description*\]**  
Set group description.

**add_extension *group* *extension***  
Add an extension to the group.

**remove_extension *group* *extension***  
Remove an extension.

**add_attribute *group* *attribute*=*value***  
Add an LDAP attribute.

**del_attribute *group* *attribute*=*value***  
Remove an LDAP attribute.

**add_object_class *group* *class***  
Add an LDAP object class.

**del_object_class *group* *class***  
Remove an LDAP object class.

**show_ldif *group* \[**-a** *attribute1,attribute2*\]**  
Show LDIF representation of the group. Use **-a** to show only given
attributes.

## Import/Export

**export \[**--password** *PASS*\] *group***  
Export group configuration.

**remove_orphans *group***  
Remove orphaned object references.

# OPTIONS

## Display Options

**-a**  
Show all groups (across all units).

**-z *SIZE***  
Limit output size.

**--fields *FIELD1,FIELD2***  
Display only specified fields.

**--role-limit *N***  
Limit number of roles shown.

**--token-limit *N***  
Limit number of tokens shown.

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

## Token Options

**--sign**  
Sign the object with default tags.

**--tags *tag1,tag2***  
Add tags to signature.

**--no-auto-sign**  
Do not automatically sign when adding a token.

**--keep-sign**  
Do not remove any signature when removing a token.

## General Options

**--keep-acls**  
Preserve ACLs when moving group.

**--password *PASS***  
Password for encrypting exports.

Global options are available for all commands. See **otpme**(1) for
details.

# CONFIG PARAMETERS

Configuration parameters can be set with the **config** command and
displayed with **show_config**. For a complete description of all
available parameters and their applicable object types, see
**otpme**(7).

# EXAMPLES

## Managing Groups

**otpme-group add developers**  
Create a new group

**otpme-group add --attributes gidNumber=1001 developers**  
Create group with specific GID

**otpme-group list_users developers**  
List users in the group

**otpme-group list_default_group_users developers**  
List users with this as default group

## Assigning Tokens and Roles

**otpme-group add_token developers alice/totp**  
Add a token to the group

**otpme-group add_role developers DEV_ROLE**  
Add a role to the group

## LDAP

**otpme-group show_ldif developers**  
Show LDIF representation

**otpme-group show_ldif developers -a cn,gidNumber**  
Show only specific LDAP attributes

# FILES

*/var/lib/otpme/*  
OTPme data directory

# SEE ALSO

**otpme**(1), **otpme**(7), **otpme-user**(1), **otpme-role**(1),
**otpme-token**(1), **otpme-policy**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
