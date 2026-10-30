# NAME

otpme-aclgroup - manage OTPme ACL groups

# SYNOPSIS

**otpme-aclgroup** *command* \[*options*\] \[*aclgroup*\]

# DESCRIPTION

**otpme-aclgroup** manages ACL groups. An ACL group is a set of ACLs.
You give the group on an object instead of giving the ACLs one by one.

Each entry of a group names an object type and an ACL, for example
**user:edit:attribute** or **token:view:initial_secret**. On an object
the group grants the entries for the type of that object, and nothing
else. On a user it grants the **user:** entries, on a token the
**token:** entries.

A group is given with **add_acl** of the object, as **@***group*, in
place of an ACL:

> **@*group***  
> On the object itself.
>
> **+@*group***  
> On the members of the unit, or on the tokens of the user.
>
> **++@*group***  
> On the whole tree below the unit: its sub units, their members, and
> the tokens of the users in it.

**+@***group* and **++@***group* do not count on the unit or user
itself. Give **@***group* as well for that, for example
**@usermanager,++@usermanager**.

A group of another site is written as **@***site***/***group*.

Change a group, and the change counts at once on every object the group
is given on. Nothing has to be written to those objects again.

A group can be a member of another group, the same way as a role in a
role. The member then inherits the entries of the other group, and of
every group above it. A member that would inherit from itself is
refused.

A disabled group grants nothing, and passes nothing on to its members.

## Base Groups

Every site has these groups:

**realm_user**  
What every user of the realm may see. The role **REALM_USER** has it on
the site and on the whole tree below it. It holds **view_public** on the
site, units, users, groups, roles, hosts and nodes, and
**view:attribute** on the site, units, users and groups. That is what an
LDAP client and **otpme-shell** need. Access groups, clients, policies
and the other object types are not in it: a user does not see them.

**usermanager**  
Add, change and delete users in a unit, add tokens to them, and see the
secret and the PIN of a new token (**view:initial_secret**,
**view:initial_pin**, see **otpme-token**(1)). No temporary passwords.

**useradmin**  
Everything of **usermanager**, and more: move and rename users and
tokens, keys, policies, temporary passwords, and the other token ACLs.

**groupmanager**  
Add and delete groups in a unit, and add and remove their members.

**get_acls** shows the exact entries. OTPme sets them, and an update of
OTPme may add new ones. You cannot change their entries, rename them or
delete them. You can make your own groups members of them, to inherit
their entries and add your own.

# COMMANDS

## ACL Group Management

**add *aclgroup***  
Create a new ACL group.  
Needs the ACL **add:aclgroup** on the unit.

**del *aclgroup***  
Delete an ACL group. It says how many members it has, and on how many
objects it is given. The ACLs that name it stay on those objects, as
orphans; **remove_orphans** of an object takes them away.

**show \[*aclgroup*\]**  
Show ACL groups, with their entries and members.

<!-- -->

**show_oid \[**--full**\] *aclgroup***  
Show the OID of the ACL group:
**aclgroup\|\<realm\>/\<site\>/\<name\>**. With **--full** the full OID,
which names the unit as well:
**aclgroup\|\<realm\>/\<site\>/\<unit_path\>/\<name\>**.  
Needs the ACL **view_public:object**.

**show_uuid *aclgroup***  
Show the UUID of the ACL group.  
Needs the ACL **view_public:object**.

<!-- -->

**list \[*regex*\]**  
List ACL groups, optionally filtered by regex pattern.

**enable *aclgroup***  
Enable a disabled ACL group.

**disable *aclgroup***  
Disable an ACL group without deleting it. It grants nothing until it is
enabled again.

**rename *aclgroup* *new_name***  
Rename an ACL group. The objects it is given on keep it: they name it by
UUID.

**move \[**--keep-acls**\] *aclgroup* *unit***  
Move the ACL group to a different unit.

**touch *aclgroup***  
Re-index the object to fix potential index problems.

**auto_disable *aclgroup* *time***  
Set auto-disable time, for example to let a delegation end by itself. It
is either a relative time with a leading **+**, e.g. **+30D**, or an
absolute one, e.g. **"09:53 13.06.2023"**. The units are **s**, **m**,
**h**, **D**, **W**, **M** and **Y**, see **otpme**(7). **0** removes
it.

## Entries

**add_entry *aclgroup* *object_type***:***acl*\[**,***object_type***:***acl*\]**  
Add entries to the ACL group. The ACL must be one the object type has;
**\_show_supported_acls** of an object of that type lists them.  
Needs the ACL **add:entry**.

**remove_entry *aclgroup* *object_type***:***acl*\[**,***object_type***:***acl*\]**  
Remove entries from the ACL group.  
Needs the ACL **remove:entry**.

**get_acls \[**-r**\] *aclgroup***  
Show the entries of the ACL group. With **-r** also the entries it
inherits, each with the group it comes from.  
Needs the ACL **view:entries**.

## Members

**add_aclgroup *aclgroup* *member***  
Make *member* a member of the ACL group. *member* then inherits the
entries of the ACL group.  
Needs the ACL **add:aclgroup** on the ACL group.

**remove_aclgroup *aclgroup* *member***  
Take *member* out of the ACL group. A UUID is taken as well, which is
how a member that is gone is cleared out.  
Needs the ACL **remove:aclgroup**.

**list_aclgroups \[**-r**\] *aclgroup***  
List the members of the ACL group. With **-r** also their members, and
so on.  
Needs the ACL **view:aclgroups**.

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

**changelog *aclgroup***  
Show the changelog of the ACL group. Needs the ACL **view:changelog**.

**edit_changelog *aclgroup* *entry_id* *comment***  
Set the comment of that entry, or replace the one it has. Needs the ACL
**edit:changelog**.

**del_changelog *aclgroup* *entry_id***  
Remove the comment of that entry. The entry itself stays, and an entry
without a comment is refused. Needs the ACL **edit:changelog**.

**clear_changelog *aclgroup***  
Remove every entry of the changelog.  
This needs more than the ACL **clear:changelog**: the config parameter
**allow_changelog_clearing** has to allow it (see **otpme**(7)).

## Policy Management

A *policy* is the name of a policy, not a path. It is looked for in the
site of the ACL group. Which policies there are, and what each of them
does, is in **otpme-policy**(1).

**add_policy *aclgroup* *policy***  
Attach a policy to the ACL group.  
Needs the ACL **assign:policy**.

**remove_policy *aclgroup* *policy***  
Remove a policy from the ACL group.  
Needs the ACL **remove:policy**.

**list_policies \[**--return-type** *TYPE*\] \[**--policy-types** *t1,t2*\] *aclgroup***  
List the policies attached to the ACL group.  
Needs the ACL **view:policies**.

## ACL Management

These are the ACLs on the ACL group itself: who may change it.

**add_acl *aclgroup* *owner_type* *owner* *acl***  
Add an access control entry.

**del_acl *aclgroup* *acl***  
Remove an access control entry.

**list_acls *aclgroup***  
Show the ACLs on the ACL group.

**enable_acl_inheritance *aclgroup***  
Let a move of the ACL group swap its default ACLs.  
Needs the ACL **enable:acl_inheritance**.

**disable_acl_inheritance *aclgroup***  
A move leaves the ACLs of the ACL group as they are again.  
Needs the ACL **disable:acl_inheritance**.

## Configuration

**config \[**-a**\] \[**-d**\] *aclgroup* *parameter* \[*value*\]**  
Set, append to or delete a config parameter.

**get_config *aclgroup* *parameter***  
Show a config parameter.

**description *aclgroup* \[*description*\]**  
Set the description of the ACL group.

**info \[**--language** *LANG*\] *aclgroup* \[*info*\]**  
Set free-form info text. If *info* is omitted, the current info text is
opened in the editor specified by the **EDITOR** environment variable.

**dump_info \[**--language** *LANG*\] *aclgroup***  
Dump the info text to stdout.

## Import/Export

**export \[**--password** *PASS*\] *aclgroup***  
Export the configuration of the ACL group.

**remove_orphans *aclgroup***  
Remove members that are gone.

# OPTIONS

## Display Options

**-a**  
Show all ACL groups.

**-z *SIZE***  
Limit output size.

**--fields *FIELD1,FIELD2***  
Display only specified fields.

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

## General Options

**-r**  
Recursive, for **get_acls** and **list_aclgroups**.

**--keep-acls**  
Preserve ACLs when moving the ACL group.

**--password *PASS***  
Password for encrypting exports.

Global options are available for all commands. See **otpme**(1) for
details.

# EXAMPLES

**otpme-aclgroup get_acls usermanager**  
Show what the base group **usermanager** holds.

**otpme-unit add_acl linux/users role helpdesk @usermanager,++@usermanager**  
Let the role **helpdesk** manage the users of the unit **linux/users**
and its sub units, and their tokens. **@usermanager** lets it add users
to **linux/users** itself, **++@usermanager** counts below it.

**otpme-aclgroup add it-user-manager**  
Create an ACL group of your own.

**otpme-aclgroup add_aclgroup usermanager it-user-manager**  
Let **it-user-manager** inherit everything of **usermanager**.

**otpme-aclgroup add_entry it-user-manager user:set_temp_password,token:set_temp_password**  
Add what **usermanager** does not have.

**otpme-aclgroup get_acls -r it-user-manager**  
Show its entries and the ones it inherits.

**otpme-unit add_acl linux/users role helpdesk @it-user-manager,++@it-user-manager**  
Give it on the unit.

**otpme-aclgroup auto_disable it-user-manager +30D**  
End the delegation in 30 days.

# AUTH ON ACTION HOOKS

An auth on action policy can ask for a login again before these actions.
See **Auth On Action Policy** in **otpme-policy**(1). An aclgroup has
the hooks every object type has, and these:

> add_aclgroup, add_entry, remove_aclgroup, remove_entry.

# FILES

*/var/lib/otpme/*  
OTPme data directory

# SEE ALSO

**otpme**(1), **otpme**(7), **otpme-unit**(1), **otpme-role**(1),
**otpme-user**(1), **otpme-token**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
