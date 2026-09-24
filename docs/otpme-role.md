# NAME

otpme-role - manage OTPme roles

# SYNOPSIS

**otpme-role** *command* \[*options*\] \[*role*\]

# DESCRIPTION

**otpme-role** manages roles in the OTPme system. Roles are groups of
tokens or other roles that can be nested.

# COMMANDS

## Role Management

**add \[**--groups** *group1,group2*\] \[**--roles** *role1,role2*\] *role***  
Create a new role. Optionally add it directly to groups or other roles.

**del *role***  
Delete a role.

**show \[*role*\]**  
Display role information. Without arguments, shows all roles.

**list \[*regex*\]**  
List roles, optionally filtered by regex pattern.

**enable \[**--share-notify**\|**--no-share-notify**\] \[**--no-persist-mount**\] *role***  
Enable a disabled role.

**--share-notify**  
Send notification to all online hosts on new share permissions.

**--no-share-notify**  
Do not send notification to all online hosts on new share permissions.

**--no-persist-mount**  
Do not persist new share mounts on hosts.

**disable \[**--share-notify**\|**--no-share-notify**\] \[**--no-persist-mount**\] *role***  
Disable a role without deleting it.

**--share-notify**  
Send notification to all online hosts on revoked share permissions.

**--no-share-notify**  
Do not send notification to all online hosts on revoked share
permissions.

**--no-persist-mount**  
Keep persisted share mounts on hosts (transient unmount only).

**rename *role* *new_name***  
Rename a role.

**move \[**--keep-acls**\] *role* *unit***  
Move role to a different unit.

**touch *role***  
Re-index the object to fix potential index problems.

## Token Assignment

**add_token \[**-i** *interfaces*\] \[**--no-auto-sign**\] \[**--sign** **--tags** *tag1,tag2*\] \[**--share-notify**\|**--no-share-notify**\] \[**--no-persist-mount**\] \[**--skip-portal-token**\] *role* *token_path***  
Add a token to the role. Use **-i** to limit login to specific
interfaces (e.g. tty, gui, ssh). If the token is the SSO token of a
site's portal (its name is that site's **default_sso_token_name**), the
tokens the portal manages for the user are added as well, after a
confirmation, with the same options. **--skip-portal-token** adds only
the given token.

**--share-notify**  
Send notification to all online hosts on new share permissions.

**--no-share-notify**  
Do not send notification to all online hosts on new share permissions.

**--no-persist-mount**  
Do not persist new share mounts on hosts.

**remove_token \[**--keep-sign**\] \[**--share-notify**\|**--no-share-notify**\] \[**--no-persist-mount**\] \[**--skip-portal-token**\] *role* *token_path***  
Remove a token from the role. If the token is the SSO token of a site's
portal, the tokens the portal manages for the user are removed as well,
after a confirmation, with the same options. **--skip-portal-token**
removes only the given token.

**--share-notify**  
Send notification to all online hosts on revoked share permissions.

**--no-share-notify**  
Do not send notification to all online hosts on revoked share
permissions.

**--no-persist-mount**  
Keep persisted share mounts on hosts (transient unmount only).

**list_tokens \[**--return-type** *TYPE*\] \[**--token-types** *t1,t2*\] *role***  
List tokens assigned to the role. Use **--return-type** to select the
attribute returned (**name**, **read_oid**, **full_oid**, **uuid**).

## Role Nesting

**add_role \[**--share-notify**\|**--no-share-notify**\] \[**--no-persist-mount**\] *role* *child_role***  
Add a child role to this role.

**--share-notify**  
Send notification to all online hosts on new share permissions.

**--no-share-notify**  
Do not send notification to all online hosts on new share permissions.

**--no-persist-mount**  
Do not persist new share mounts on hosts.

**remove_role \[**--share-notify**\|**--no-share-notify**\] \[**--no-persist-mount**\] *role* *child_role***  
Remove a child role from this role.

**--share-notify**  
Send notification to all online hosts on revoked share permissions.

**--no-share-notify**  
Do not send notification to all online hosts on revoked share
permissions.

**--no-persist-mount**  
Keep persisted share mounts on hosts (transient unmount only).

**list_roles \[**-r**\] *role***  
List roles assigned to the role. Use **-r** for recursive listing.

**find_acls *role***  
Find the ACLs this role holds on other objects.

**find_scopes \[**--return-type** *TYPE*\] *role***  
Find OIDC scopes the role is assigned to. **--return-type** selects the
attribute to return (**name**, **read_oid**, **full_oid**, **uuid**).

**find_shares \[**-r**\] \[**--return-type** *TYPE*\] *role***  
Find shares granted via this role. **-r** walks child roles too.

## VLAN Assignment

A role is not assigned a VLAN from here. The VLAN names the role, not
the other way round, so the assignment belongs to the site that runs the
network (see **otpme-vlan**(1)):

> **otpme-vlan add_role *vlan* *role***

Every token, host and device of the role then gets that VLAN during
802.1x or MAB port authentication, and so does every role nested in it.
The more specific assignment wins: a VLAN naming a token itself beats
one naming its role, and a VLAN naming a nested role beats one naming
the role it is nested in. So a role can be given a VLAN of its own
without taking the outer role out of its VLAN.

Only VLANs of the site answering the RADIUS request are looked at. Where
no VLAN names the role or its members, the **vlans** config parameter of
the token, user, host or device decides (see **otpme**(7)).

## User and Group Listing

**list_users \[**--return-type** *TYPE*\] *role***  
List users of the role. Use **--return-type** to select the attribute
returned (**name**, **read_oid**, **full_oid**, **uuid**).

**list_dynamic_groups *role***  
List dynamic groups of the role.

## Host and Device Assignment

**add_host *role* *host***  
Add a host to the role.

**remove_host *role* *host***  
Remove a host from the role.

**list_hosts *role***  
List hosts assigned to the role.

**add_device *role* *device***  
Add a device to the role.

**remove_device *role* *device***  
Remove a device from the role.

**list_devices *role***  
List devices assigned to the role.

## Dynamic Groups

**add_dynamic_group *role* *group***  
Add a dynamic group to the role.

**remove_dynamic_group *role* *group***  
Remove a dynamic group from the role.

## Sync Users

**add_sync_user *role* *user***  
Add a sync user to the role.

**remove_sync_user *role* *user***  
Remove a sync user from the role.

**list_sync_users \[**--return-type** *TYPE*\] *role***  
List sync users of the role. Use **--return-type** to select the
attribute returned (**name**, **read_oid**, **full_oid**, **uuid**).

## Policy Management

A *policy* is the name of a policy, not a path. It is looked for in the
site of the role. Which policies there are, and what each of them does,
is in **otpme-policy**(1).

Attaching and detaching ask before they change anything; the global
option **-f** skips the question.

**add_policy *role* *policy***  
Attach a policy to the role.  
A policy has a list of object types it is for; one that does not name
**role** is refused. So is a second policy of a type that allows only
one per object.  
Needs the ACL **assign:policy**.

**remove_policy *role* *policy***  
Remove a policy from the role.  
Needs the ACL **remove:policy**, and that one verbatim: a plain
**remove** does not cover it. Detaching a policy takes away what it
enforces, so it must not be cheaper than attaching one.

**list_policies \[**--return-type** *TYPE*\] \[**--policy-types** *t1,t2*\] *role***  
List the policies attached to the role. Use **--return-type** to select
the attribute returned (**name**, **read_oid**, **full_oid**, **uuid**).
Use **--policy-types** to list only policies of the given types; these
are policy types, not policy names.  
Needs the ACL **view:policies**.

## ACL Management

An ACL says what somebody may do with this role. The somebody is a role
or a token, never a user.

What the three forms *acl*, **+***acl* and **++***acl* mean, and which
ACLs exist, is under **ACLs** in **otpme**(7).

A command that changes something asks first; the global option **-f**
skips the question.

The other direction, the ACLs this role holds on other objects, is
**find_acls** under **Listing** above.

**add_acl *role* *owner_type* *owner* *acl*\[**:***value*\]**  
Give a role or a token an ACL on this role.  
*owner_type* is **role** or **token**, and *owner* the path of that role
or token. An ACL may carry a value, for example **view:tokens**.  
Needs the ACL **add:acl**.

**del_acl *role* *acl***  
Take that ACL away again.  
Here the *acl* is the whole entry, owner and all, the way **list_acls**
prints it: **role:berlin/sw-admins:view**.  
Needs the ACL **delete:acl**.

**list_acls *role***  
Show the ACLs that lie on this role, i.e. who may do what with it. Needs
the ACL **view:acl**.

**enable_acl_inheritance *role***  
Let the role inherit the default ACLs of the unit above it. It does not
by default.

Only default ACLs are inherited. An ordinary ACL on the unit never is.

Moving a role into another unit is the one place that asks something
else as well: the site admin role **SITE_ADMIN** gets neither the
default ACLs of the new unit nor loses those of the old one.

Needs the ACL **enable:acl_inheritance**.

**disable_acl_inheritance *role***  
Stop inheriting them. Only the ACLs on the role itself count from then
on.  
Needs the ACL **disable:acl_inheritance**.

## Extension and Attribute Management

**add_extension *role* *extension***  
Add an extension to the role.

**remove_extension *role* *extension***  
Remove an extension from the role.

**add_attribute *role* *attribute*=*value***  
Add an LDAP attribute to the role.

**del_attribute *role* *attribute*=*value***  
Remove an LDAP attribute from the role.

**add_object_class *role* *class***  
Add an LDAP object class to the role.

**del_object_class *role* *class***  
Remove an LDAP object class from the role.

**show_ldif \[**-a** *attributes*\] *role***  
Show LDIF representation of the role. Use **-a** to show only specific
attributes.

## Configuration and Attributes

**config \[**-d**\] \[**-a**\] *role* *parameter* \[*value*\]**  
Set a configuration parameter. Use **-d** to delete (reset to default)
or **-a** to append the value to a list-typed parameter.

**show_config *role* \[*parameter*\]**  
Show all configuration parameters.

**get_config *role* *parameter***  
Show the value of a single configuration parameter.

**description *role* \[*description*\]**  
Set role description.

**info \[**--language** *LANG*\] *role* \[*info*\]**  
Set free-form info text. If *info* is omitted, the current info text is
opened in the editor specified by the **EDITOR** environment variable.  
Without **--language** the text is the administrator's own note about
the object, which no user is ever shown. A text written with a language
is one for the users of that language: a role named in
**device_token_roles** shows it on the SSO portal, in the language of
whoever is looking, see **otpme**(7).

**dump_info \[**--language** *LANG*\] *role***  
Dump the info text to stdout.

## Object Changelog

Every change to the object writes an entry: who made it, when, and what
was done. A change can carry a comment of its own, through the global
option **--changelog**.

An *entry_id* is the number the listing shows in front of an entry,
counted from 0.

Only the comment of an entry can be changed or removed. What was done
and by whom stays as it is.

A command that changes something asks first; the global option **-f**
skips the question.

**changelog *role***  
Show the changelog of the role. Needs the ACL **view:changelog**.

**edit_changelog *role* *entry_id* *comment***  
Set the comment of that entry, or replace the one it has. Needs the ACL
**edit:changelog**.

**del_changelog *role* *entry_id***  
Remove the comment of that entry. The entry itself stays, and an entry
without a comment is refused. Needs the ACL **edit:changelog**.

**clear_changelog *role***  
Remove every entry of the changelog.  
This needs more than the ACL **clear:changelog**: the config parameter
**allow_changelog_clearing** has to allow it (see **otpme**(7)). It is
true by default, but where no value is found at all, clearing is
refused. OTPme asks the token you are signed in with first, then the
object.

## Import/Export

**export \[**--password** *PASS*\] *role***  
Export role configuration.

**remove_orphans *role***  
Remove orphaned object references.

# OPTIONS

## Display Options

**-a**  
Show all roles (across all units).

**-z *SIZE***  
Limit output size.

**--fields *FIELD1,FIELD2***  
Display only specified fields.

**--token-limit *N***  
Limit number of tokens shown.

**--role-limit *N***  
Limit number of roles shown.

**--accessgroup-limit *N***  
Limit number of access groups shown.

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

## Token Options

**-i *interfaces***  
Limit login to given interfaces (e.g. tty, gui, ssh).

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
Preserve ACLs when moving role.

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

## Managing Roles

**otpme-role add admins**  
Create a new role

**otpme-role add --groups sysadmins --roles operators**  
Create a role and add it to groups and roles

## Token Assignment

**otpme-role add_token admins admin/totp**  
Add admin's TOTP token to the role

**otpme-role add_token -i ssh admins admin/ssh_key**  
Add SSH key for SSH interface only

## Role Nesting

**otpme-role add_role super_admins admins**  
Add admins role as child of super_admins

**otpme-role list_roles -r super_admins**  
List all nested roles recursively

## VLAN Assignment

**otpme-vlan add_role employees_vlan employees**  
Put every member of the role into a VLAN

**otpme-vlan add_role admin_vlan admins**  
Give a role nested in "employees" a VLAN of its own. Its members get it
instead of the VLAN of "employees"

## Policy Assignment

**otpme-role add_policy admins require_2fa**  
Attach a policy to the role

# FILES

*/var/lib/otpme/*  
OTPme data directory

# SEE ALSO

**otpme**(1), **otpme**(7), **otpme-user**(1), **otpme-token**(1),
**otpme-group**(1), **otpme-accessgroup**(1), **otpme-vlan**(1),
**otpme-policy**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
