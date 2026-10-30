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

**add \[**--attributes** *attr=value,...*\] *group***  
Add a group. With a path, e.g. **linux/staff**, it goes into that unit;
else into the unit a **defaultunits** policy names, see
**otpme-policy**(1), or into **groups**. The name is unique in the
realm, over all sites.  
**--attributes** sets attributes of the posix extension, e.g.
**gidNumber=5000**; one it does not have is refused. Without
**gidNumber** the group gets the next free one, see **idrange** in
**otpme-policy**(1).  
Needs **add:group** on the unit.

**del \[**--no-trash**\] *group***  
Delete the group. It goes to the trash, see **otpme-trash**(1);
**--no-trash** deletes it right away.  
A group that still has tokens or roles, or is the default group of a
user, is not deleted; the refusal names them. **-f** deletes it anyway,
and what held it keeps a reference to something that is gone;
**remove_orphans** clears it up. The groups the realm and the sites come
with (**root**, **realmusers** and the group named like each site)
cannot be deleted.  
Needs **delete:object** on the group or **delete:group** on the unit.

**show \[**-a**\] \[**-z** *N*\] \[**--fields** *F1,F2*\] \[**--limit** *N*\] \[**--role-limit** *N*\] \[**--token-limit** *N*\] \[**--host-limit** *N*\] \[**--policy-limit** *N*\] \[**--sort-by** *field*\] \[**--reverse**\] \[**--raw**\] \[**--csv**\] \[**--csv-sep** *sep*\] \[*group*\]**  
Without a group: a table of all of them, with their unit, status, roles,
tokens, hosts, sync users, policies, ACL inheritance and description.

**-a**  
Also the groups you may only look at, not just the ones you may change.

**-z *N***  
How many groups to print.

**--fields *F1,F2***  
Print these columns and no others, in the order they are named. A name
with a **+** in front is added to the columns that are shown anyway, and
one with a **-** is left out of them.

**--limit *N***  
How many of each kind to print per group: roles, tokens, hosts, sync
users, policies.

**--role-limit *N*, **--token-limit** *N*, **--host-limit** *N*, **--policy-limit** *N***  
The same for one of them.

**--sort-by *field*, **--reverse****  
Which column to sort by, and the other way round.

**--raw, **--csv**, **--csv-sep** *sep***  
**--raw** leaves the header and the borders out, **--csv** prints one
row per line with **;** between the columns, and **--csv-sep** uses
another separator.

A column you may not see says **-**. With a group named, this prints the
object itself instead of a table row, one value per line. A name that is
no group is taken as a regex.

**show_oid \[**--full**\] *group***  
Show the OID of the group: **group\|\<realm\>/\<name\>**. With
**--full** the full OID, which names the site and unit as well:
**group\|\<realm\>/\<site\>/\<unit_path\>/\<name\>**.  
Needs the ACL **view_public:object**.

**show_uuid *group***  
Show the UUID of the group.  
Needs the ACL **view_public:object**.

**list \[**-a**\] \[**--attribute** *attribute*\] \[*regex*\]**  
List the group names, and with a regex only those that match it. You get
the groups you may change; **-a** adds those you may only look at.
**--attribute** matches the regex against that attribute instead of the
name.

**enable \[**--share-notify**\|**--no-share-notify**\] \[**--no-persist-mount**\] *group***  
**disable \[**--share-notify**\|**--no-share-notify**\] \[**--no-persist-mount**\] *group***  
Only an enabled group counts for the shares it is on: its hosts are
hosts of a share that is limited to hosts. Disabling it takes them away
from there. Logins and the group on the hosts stay as they are. Tables
show the status.  
Needs **enable:object** or **disable:object**.

**--share-notify, **--no-share-notify****  
Whether the users of those shares are told, so that their hosts mount or
unmount. Without either the share decides (**share_notifications**).

**--no-persist-mount**  
Mount or unmount now, but leave the shares an offline login mounts as
they are: after **enable** an offline login does not mount the share,
after **disable** it still does.

**rename *group* *new_name***  
Rename the group. The new name must not be in use anywhere in the realm.
The groups the realm and the sites come with cannot be renamed.  
Needs **rename:object**.

**move \[**--keep-acls**\] *group* *unit***  
Move the group into another unit. The group keeps its ACLs; where ACL
inheritance is on for it (off for groups by default, see
**enable_acl_inheritance**), the default ACLs of the old unit are taken
away and those of the new one given. **--keep-acls** keeps all ACLs as
they are.  
With a full path, */\<realm\>/\<site\>/\<unit\>*, the group moves to
that site; its policies go with it by name. The groups the realm and the
sites come with cannot be moved.  
Needs **move** on the group and **add:group** on the unit.

**touch *group***  
Write the index entries of the group again.  
Needs **touch**.

**auto_disable *group* *time***  
Set auto-disable time. It is either a relative time with a leading
**+**, e.g. **+30D**, or an absolute one, e.g. **"09:53 13.06.2023"**.
The units are **s**, **m**, **h**, **D**, **W**, **M** and **Y**, see
**otpme**(7). A relative time counts from when it is set, and again from
when the group is enabled. **0** removes it. It is refused for an object
the realm or a site comes with, e.g. the admin user; a time set on one
before does nothing.  
Needs **edit:auto_disable**.

## Token and Role Assignment

A group's members are the owners of its tokens: on the hosts and in LDAP
the group lists them (**memberUid**). A role in the group counts with
its tokens, and with those of the roles it holds. The users whose
default group it is are members as well. A disabled token or role counts
for nothing.

**add_token \[**--sign**\] \[**--tags** *tag1,tag2*\] \[**--no-auto-sign**\] *group* *token***  
Put a token (*\<user\>/\<token\>*) into the group.  
It is signed when you ask for it, or when auto_sign is on: for you, or
as config parameter of the group. The signature is made with your login
token and says the token is in this group. A token signer of a host that
wants this tag (**otpme-tool add_signer --tag group:\<group\>**) lets
only the SSH keys of signed members in, see **otpme-tool**(1).  
Needs **add:token**.

**--sign**  
Sign, where nothing above asked for it. On a token that cannot be signed
this is an error.

**--tags *tag1,tag2***  
Put more tags into the signature.

**--no-auto-sign**  
Do not sign this time.

**remove_token \[**--keep-sign**\] *group* *token***  
Take the token out of the group. The signatures made for this group go
with it, each after a question; **--keep-sign** leaves them. A token
that is gone is taken out by its UUID.  
Needs **remove:token**.

**list_tokens \[**--return-type** *type*\] \[**--token-types** *t1,t2*\] *group***  
The tokens put into the group, disabled ones too; not those of its
roles. **--return-type** picks what is printed: **rel_path** (default,
*\<user\>/\<token\>*), **read_oid**, **full_oid** or **uuid**.
**--token-types** narrows it to those types, e.g. **hotp,totp**.  
Needs **view:tokens**.

**add_role *group* *role***  
Put a role into the group. One of another site is written as
*\<site\>/\<role\>*.  
Needs **add:role**.

**remove_role *group* *role***  
Take the role out again. A role that is gone is taken out by its UUID.  
Needs **remove:role**.

**list_roles \[**--return-type** *type*\] *group***  
The roles in the group, disabled ones too; one of another site as
*\<site\>/\<role\>*. **--return-type** picks what is printed: **name**
(default), **read_oid**, **full_oid** or **uuid**.  
Needs **view:roles**.

## User Management

Who is a member of the group on the hosts is in its attribute
**memberUid**: **show_ldif** *group* **-a memberUid**, see **Token and
Role Assignment**. The two lists here are parts of it, and they list
disabled ones too.

**list_users \[**--return-type** *type*\] *group***  
The users the tokens put into the group belong to; one user with three
tokens is named once. Not those that come through a role.
**--return-type** picks what is printed: **name** (default),
**read_oid**, **full_oid** or **uuid**.  
Needs **view:tokens**.

**list_default_group_users \[**--return-type** *type*\] *group***  
The users whose default group this is. **--return-type** as above.  
Needs **view:default_group_users**.

## Host Management

The hosts of a group count for one thing: on a share that is limited to
hosts and has the group (**otpme-share add_group**), they are hosts of
the share, as long as the group is enabled. Logins and the group on the
hosts do not depend on them.

**add_host \[**--share-notify**\|**--no-share-notify**\] \[**--no-persist-mount**\] *group* *host***  
Put a host into the group. Host names are unique in the realm, so the
host is given by its name alone, whatever site it is in. A node cannot
be put in.  
Needs **add:host**.

**--share-notify, **--no-share-notify****  
Whether the users of those shares are told, so that the host mounts the
share. Without either the share decides (**share_notifications**).

**--no-persist-mount**  
Mount now, but an offline login does not mount the share.

**remove_host \[**--share-notify**\|**--no-share-notify**\] \[**--no-persist-mount**\] *group* *host***  
Take the host out again. On the shares it loses, it is told to unmount,
unless it is still on the share some other way. A host that is gone is
taken out by its UUID.  
Needs **remove:host**.

**--share-notify, **--no-share-notify****  
As above, for the unmount.

**--no-persist-mount**  
Unmount now, but an offline login still mounts the share.

**list_hosts \[**--return-type** *type*\] *group***  
The hosts in the group, disabled ones too. **--return-type** picks what
is printed: **name** (default), **read_oid**, **full_oid** or
**uuid**.  
Needs **view:hosts**.

## Sync User Management

A sync user is a user whose account is copied to a host without any
token of theirs going with it. A group passes its sync users on to the
hosts that name it as sync group (**otpme-host add_sync_group**, with
**enable_sync_groups**), together with the sync users of its roles and
of the roles inside them. A sync user is no member of the group on the
hosts.

**add_sync_user *group* *user***  
Have that user's account copied to those hosts. The user may be of any
site.  
Needs **add:sync_user**.

**remove_sync_user *group* *user***  
Stop that. A user who is gone is taken out by the UUID.  
Needs **remove:sync_user**.

**list_sync_users \[**--return-type** *type*\] *group***  
The sync users of the group, disabled ones too; not those of its roles.
**--return-type** picks what is printed: **name** (default),
**read_oid**, **full_oid** or **uuid**.  
Needs **view:sync_users**.

## Object Changelog

Every change to the object writes an entry: who made it, when, and what
was done. A change can carry a comment of its own, through the global
option **--changelog**.

Unless the **changelog** config parameter says otherwise. It is read
along the cascade (group, unit, site), and nothing is written where it
is off. Without any value anywhere it is on.

An *entry_id* is the number the listing shows in front of an entry,
counted from 0.

Only the comment of an entry can be changed or removed. What was done
and by whom stays as it is.

A command that changes something asks first; the global option **-f**
skips the question.

**changelog *group***  
Show the changelog of the group. Needs the ACL **view:changelog**.

**edit_changelog *group* *entry_id* *comment***  
Set the comment of that entry, or replace the one it has. Needs the ACL
**edit:changelog**.

**del_changelog *group* *entry_id***  
Remove the comment of that entry. The entry itself stays, and an entry
without a comment is refused. Needs the ACL **edit:changelog**.

**clear_changelog *group***  
Remove every entry of the changelog. Afterwards it holds one entry: that
it was cleared.  
This needs more than the ACL **clear:changelog**: the config parameter
**allow_changelog_clearing** has to allow it (see **otpme**(7)). It is
true by default, but where no value is found at all, clearing is
refused. A value set on the token you are signed in with counts first.
Without one, the value of the group counts, read along its cascade.

## Policy Management

A *policy* is the name of a policy, not a path. It is looked for in the
site of the group. Which policies there are, and what each of them does,
is in **otpme-policy**(1).

Two policy types fit a group: **authonaction** and **autodisable**.

Attaching and detaching ask before they change anything; the global
option **-f** skips the question.

**add_policy *group* *policy***  
Attach a policy to the group.  
A policy has a list of object types it is for; one that does not name
**group** is refused. So is a second policy of a type that allows only
one per object, even when the first one is disabled, and a policy the
group already has.  
An auto-disable policy with **-u** is refused, because a group does not
keep its last use.  
Needs the ACL **assign:policy**.

**remove_policy *group* *policy***  
Remove a policy from the group.  
Needs the ACL **remove:policy**, and that one verbatim: a plain
**remove** does not cover it. Detaching a policy takes away what it
enforces, so it must not be cheaper than attaching one.

**list_policies \[**--return-type** *TYPE*\] \[**--policy-types** *t1,t2*\] *group***  
List the policies attached to the group, the disabled ones too, marked
**(disabled)**. Use **--return-type** to select the attribute returned
(**name**, **read_oid**, **full_oid**, **uuid**); without it the names.
Only the names are marked. Use **--policy-types** to list only policies
of the given types; these are policy types, not policy names.  
Needs the ACL **view:policies**.

## ACL Management

An ACL says what somebody may do with this group. The somebody is a role
or a token, never a user.

What the three forms **acl**, **+acl** and **++acl** mean is under
**ACLs** in **otpme**(7). Which ACLs a group knows is in
**otpme-acls**(7). A group has no default ACLs, **+acl** and **++acl**:
nothing lies in a group that could get them.

Adding and removing ask first; the global option **-f** skips the
question.

**add_acl *group* *owner_type* *owner* *acl*\[:*value*\]\[,*acl*\[:*value*\]\]**  
Give a role or a token one or more ACLs on this group.  
*owner_type* is **role** or **token**. *owner* is the path of that role
or token. An ACL can carry a value, for example **view:tokens**. To give
several ACLs at once, separate them with commas:
**view:tokens,add:token**.  
Needs the ACL **add:acl**.

**del_acl *group* *acl*\[,*acl*\]**  
Take those ACLs away again.  
Here an *acl* is the whole entry, owner and all, the way **list_acls**
prints it: **role:berlin/helpdesk:view:tokens**.  
Needs the ACL **delete:acl**.

**list_acls *group***  
Show the ACLs that lie on this group, i.e. who may do what with it.  
Needs the ACL **view:acl**.

**enable_acl_inheritance *group***  
Let a move of the group swap its default ACLs: what the old unit handed
down is taken away, and what the new unit hands down is given. It does
not by default; a move then leaves the ACLs of the group as they are.

Only a move asks this. A new group gets the default ACLs of its unit,
and **add_acl -a** or **-r** on a unit reach it either way. A move with
**--keep-acls** leaves its ACLs alone all the same.

A move by somebody who does not hold **add:acl** and **delete:acl** on
the group leaves its ACLs alone as well, and says so. Otherwise moving
an object into a unit would be a way of handing yourself the default
ACLs of that unit.

Groups had it on until config version 2, which switches it off for all
of them (see **upgrade** in **otpme-site**(1)).

Needs the ACL **enable:acl_inheritance**.

**disable_acl_inheritance *group***  
A move leaves the ACLs of the group as they are again.  
Needs the ACL **disable:acl_inheritance**.

## Configuration and Attributes

**config \[**-d**\] \[**-a**\] *group* *parameter* \[*value*\]**  
Set a configuration parameter. Use **-d** to delete (reset to default)
or **-a** to append the value to a list-typed parameter.

**show_config *group* \[*parameter*\]**  
Show all configuration parameters.

**get_config *group* *parameter***  
Show the value of a single configuration parameter.

**description *group* \[*description*\]**  
Set group description.

**info \[**--language** *LANG*\] *group* \[*info*\]**  
Set free-form info text. If *info* is omitted, the current info text is
opened in the editor specified by the **EDITOR** environment variable.

**dump_info \[**--language** *LANG*\] *group***  
Dump the info text to stdout.

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

**--host-limit *N***  
Limit number of hosts shown.

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
Of **list**: match the regex against this attribute instead of the name.

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

# AUTH ON ACTION HOOKS

An auth on action policy can ask for a login again before these actions.
See **Auth On Action Policy** in **otpme-policy**(1). A group has the
hooks every object type has, and these:

> add_host, add_role, add_token, move, remove_host, remove_role,
> remove_token, set_config_parameter.

# FILES

*/var/lib/otpme/*  
OTPme data directory

# SEE ALSO

**otpme**(1), **otpme**(7), **otpme-acls**(7), **otpme-user**(1),
**otpme-role**(1), **otpme-token**(1), **otpme-policy**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
