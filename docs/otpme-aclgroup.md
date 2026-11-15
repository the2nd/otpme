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
> On the objects in the unit, or on the tokens of the user.
>
> **++@*group***  
> On the whole tree below the unit: its sub units, the objects in them,
> and the tokens of the users in it.

**+@***group* and **++@***group* are default ACLs and are handed down
like them: to what is added to the unit or user, or moved there, from
then on. To hand them to what is there already, give them with **add_acl
-a**, and **-r** for the tree below, see **otpme-unit**(1). They do not
count on the unit or user itself. Give **@***group* as well for that,
for example **@USERMANAGER,++@USERMANAGER**.

A group of another site is written as **@***site***/***group*.

Change a group, and the change counts at once on every object the group
is given on. Nothing has to be written to those objects again.

A group can have other groups of its site as members. It grants their
entries as well, and those of their members, and so on. Only who may
change the group adds members to it: what a group grants changes only
with a change of that group.

A disabled group grants nothing, and passes nothing on to the groups it
is a member of.

## Base Groups

Every site has these groups. Their names are in upper case, like those
of the base roles and access groups, and a group you add gets its name
in lower case. A name is taken either way: **@usermanager** is
**USERMANAGER**.

**REALM_USERS**  
What every user of the realm may see. The role **REALM_USER** has it on
the site and on the whole tree below it. It holds **view_public** on the
site, units, users, groups, roles, hosts and nodes, and
**view:attribute** on the site, units, users and groups. That is what an
LDAP client and **otpme-shell** need. Access groups, clients, policies
and the other object types are not in it: a user does not see them.

**USERMANAGER**  
Add, change and delete users in a unit, add tokens to them, and see the
secret and the PIN of a new token (**view:initial_secret**,
**view:initial_pin**, see **otpme-token**(1)). No temporary passwords.

**USERADMIN**  
Everything of **USERMANAGER**, and more: edit, enable, disable, rename
and move users and tokens, delete tokens, unblock users, their keys,
photos and policies, and temporary passwords.

**GROUPMANAGER**  
Add and delete groups in a unit, and add and remove their members.

**PASSUSER**  
Work with the passwords of a unit, see **otpme-pass**(1): add, delete
and rename them, their entries, keys, description and info, and the
nodes, hosts, devices and clients they belong to. Reading an entry needs
the key of the user as well, which no ACL gives. No moving, policies or
ACLs.

**get_acls** shows the exact entries. OTPme sets them, and an update of
OTPme may add new ones. You cannot change their entries or members,
rename, move, disable or delete them, or give them an auto-disable time.
Add them as members to a group of your own, to get their entries and add
your own.

# COMMANDS

## ACL Group Management

**add *aclgroup***  
Create an ACL group. With a path, e.g. **aclgroups/helpdesk/printers**,
it goes into that unit; else into the unit a **defaultunits** policy
names, see **otpme-policy**(1), or into **aclgroups**. The name is kept
in lower case; only the base groups are in upper case, see **Base
Groups**. It is unique in the site, whatever unit it is in, and may be
**max_aclgroup_name_len** long (64 by default).  
Needs **add:aclgroup** on the unit.

**del \[**--no-trash**\] *aclgroup***  
Delete the ACL group. It goes to the trash, see **otpme-trash**(1);
**--no-trash** deletes it right away. A base group cannot be deleted.  
The question says how many ACL groups have it as a member, which then no
longer grant its entries, and on how many objects it is given. The ACLs
that name it stay on those objects, as orphans; **remove_orphans** of an
object takes them away. It is taken out of the ACL groups it is a member
of.  
Needs **delete:object** on the ACL group or **delete:aclgroup** on the
unit.

**show \[**-a**\] \[**-z** *N*\] \[**--fields** *F1,F2*\] \[**--limit** *N*\] \[**--policy-limit** *N*\] \[**--sort-by** *field*\] \[**--reverse**\] \[**--raw**\] \[**--csv**\] \[**--csv-sep** *sep*\] \[*aclgroup*\]**  
Without an ACL group: a table of all of them, with their unit, status,
entries, member groups, policies, ACL inheritance and description. A
disabled member group has **(D)** after it.

**-a**  
Also the ACL groups you may only look at, not just the ones you may
change.

**-z *N***  
How many ACL groups to print.

**--fields *F1,F2***  
Print these columns and no others. The names are the ones in the header
of the table.

**--limit *N***  
How many of each kind to print per ACL group: entries, member groups,
policies. Without it 10 entries, 5 member groups and 5 policies; 30 of
each when the table has one ACL group only.

**--policy-limit *N***  
The same for the policies only.

**--sort-by *field*, **--reverse****  
Which column to sort by, and the other way round.

**--raw, **--csv**, **--csv-sep** *sep***  
**--raw** leaves the header and the borders out, **--csv** prints one
row per line with **;** between the columns, and **--csv-sep** uses
another separator.

A column you may not see says **-**. With an ACL group named, this
prints the ACL group itself, one value per line: **ENTRIES** and
**ACLGROUPS**; one you may not see is empty. That needs
**view_public:object**.

**show_oid \[**--full**\] *aclgroup***  
Show the OID of the ACL group:
**aclgroup\|\<realm\>/\<site\>/\<name\>**. With **--full** the full OID,
which names the unit as well:
**aclgroup\|\<realm\>/\<site\>/\<unit_path\>/\<name\>**.  
Needs **view_public:object**.

**show_uuid *aclgroup***  
Show the UUID of the ACL group.  
Needs **view_public:object**.

**list \[**-a**\] \[**--attribute** *attribute*\] \[*pattern*\]**  
List the ACL group names, and with a pattern only those that match it,
see **SELECTING OBJECTS** in **otpme**(1). You get the ACL groups you
may change; **-a** adds those you may only look at. **--attribute**
matches the pattern against that attribute instead of the name.

**enable *aclgroup***  
**disable *aclgroup***  
A disabled ACL group grants nothing where it is given, and the groups it
is a member of no longer get its entries. Tables show the status. A base
group cannot be disabled.  
Needs **enable:object** or **disable:object**.

**rename *aclgroup* *new_name***  
Rename the ACL group. The new name is kept in lower case and must not be
in use in the site. The objects it is given on keep it: they name it by
its UUID. A base group cannot be renamed.  
Needs **rename:object**.

**move \[**--keep-acls**\] *aclgroup* *unit***  
Move the ACL group into another unit. It keeps its ACLs; where ACL
inheritance is on for it (off for ACL groups by default, see
**enable_acl_inheritance**), the default ACLs of the old unit are taken
away and those of the new one given. **--keep-acls** keeps all ACLs as
they are. A base group cannot be moved.  
Needs **move** on the ACL group and **add:aclgroup** on the unit.

**touch *aclgroup***  
Write the index entries of the ACL group again.  
Needs **touch**.

**auto_disable *aclgroup* *time***  
Set auto-disable time, for example to let a delegation end by itself. It
is either a relative time with a leading **+**, e.g. **+30D**, or an
absolute one, e.g. **"09:53 13.06.2023"**. The units are **s**, **m**,
**h**, **D**, **W**, **M** and **Y**, see **otpme**(7). A relative time
counts from when it is set, and again from when the ACL group is
enabled. **0** removes it. A base group cannot get one.  
Needs **edit:auto_disable**.

## Entries

An entry is an object type and an ACL that type has, e.g.
**user:edit:description**. Given on an object, the group grants there
the entries for the type of that object, see DESCRIPTION. Adding and
removing ask first; the global option **-f** skips the question.

**add_entry *aclgroup* *object_type***:***acl*\[**,***object_type***:***acl*\]**  
Add entries to the ACL group. The object type is one of the tree, e.g.
**unit**, **user** or **token**, and the ACL must be one that type has;
tab completion offers them. An ACL with a value can be narrowed by one
more value: **user:edit:attribute:mail** grants less than
**user:edit:attribute**. If one of the entries is in the group already,
none is added. A base group cannot be changed.  
Needs **add:entry**.

**remove_entry *aclgroup* *object_type***:***acl*\[**,***object_type***:***acl*\]**  
Remove entries from the ACL group. They are not checked against the
type, so an entry the type no longer has can still be removed. If one of
them is not in the group, none is removed. A base group cannot be
changed.  
Needs **remove:entry**.

**get_acls \[**-r**\] *aclgroup***  
Show the entries of the ACL group, one per line.  
With **-r** also the entries it gets from its members, and from their
members, each with the group in brackets. A disabled group passes
nothing on: its entries are left out, and so are those of its members.  
Needs **view:entries**.

## Members

An ACL group grants the entries of its members as well, see DESCRIPTION.
Adding and removing ask first; the global option **-f** skips the
question.

**add_aclgroup *aclgroup* *member***  
Add *member* to the ACL group: the ACL group then grants the entries of
*member* as well, wherever it is given. *member* is an ACL group of the
same site. One that is in already is refused, and so is one that has the
ACL group among its own members, or among theirs: the group would get
its own entries back. A base group gets no members added.  
Needs **add:aclgroup** on the ACL group.

**remove_aclgroup *aclgroup* *member***  
Take *member* out of the ACL group: it no longer grants its entries. A
UUID is taken as well, for a member that is gone; **remove_orphans**
takes them all out. A base group cannot be changed.  
Needs **remove:aclgroup**.

**list_aclgroups \[**-r**\] *aclgroup***  
List the members of the ACL group, one per line; one that is gone shows
its UUID. With **-r** also their members, and so on.  
Needs **view:aclgroups**.

## Where It Is Given

**find_acls *aclgroup***  
List the objects the ACL group is given on, one ACL per line: the
object, then to whom and how it is given:

    unit|example.org/berlin/passwords role:berlin/helpdesk:++@PASSUSER

Objects of other sites are listed too: they may give a group of this
site as **@site/group**. A recursive ACL is on the objects below the
unit as well, so each of them has a line of its own. An owner that is
gone shows its UUID.  
A group that has it as a member grants its entries as well, where that
group is given. Those ACLs are listed too, with the way there in
brackets, and so on up; a disabled group passes nothing on and is left
out:

    unit|example.org/berlin/linux role:berlin/helpdesk:@mine (PASSUSER in mine)
    unit|example.org/berlin/servers role:berlin/admins:@top (PASSUSER in mine in top)

Only an admin may run it.

## Object Changelog

Every change to the object writes an entry: who made it, when, and what
was done. A change can carry a comment of its own, through the global
option **--changelog**.

Unless the **changelog** config parameter says otherwise. It is read
along the cascade (ACL group, unit, site), and nothing is written where
it is off. Without any value anywhere it is on.

OTPme keeps the entries of a base group in line with the code without an
entry.

An *entry_id* is the number the listing shows in front of an entry,
counted from 0.

Only the comment of an entry can be changed or removed. What was done
and by whom stays as it is.

A command that changes something asks first; the global option **-f**
skips the question.

**changelog *aclgroup***  
Show the changelog of the ACL group, one entry per line: its *entry_id*,
the time, who made the change and what was done, then a detail in round
brackets and the comment in square brackets where there are any. Needs
the ACL **view:changelog**.

**edit_changelog *aclgroup* *entry_id* *comment***  
Set the comment of that entry, or replace the one it has. That writes an
entry of its own. Needs the ACL **edit:changelog**.

**del_changelog *aclgroup* *entry_id***  
Remove the comment of that entry. The entry itself stays, and an entry
without a comment is refused. That writes an entry of its own. Needs the
ACL **edit:changelog**.

**clear_changelog *aclgroup***  
Remove every entry of the changelog. Afterwards it holds one entry: that
it was cleared.  
This needs more than the ACL **clear:changelog**: the config parameter
**allow_changelog_clearing** has to allow it (see **otpme**(7)). It is
true by default, but where no value is found at all, clearing is
refused. A value set on the token you are signed in with counts first.
Without one, the value of the object counts, read along its cascade.

## Policy Management

A *policy* is the name of a policy, not a path. It is looked for in the
site of the ACL group. Which policies there are, and what each of them
does, is in **otpme-policy**(1).

Two policy types fit an ACL group:

-   **authonaction** asks for a login again before the actions of the
    ACL group, see **AUTH ON ACTION HOOKS**.

-   **autodisable** disables the ACL group after a while; it then grants
    nothing, see **disable**. It is refused for a base group, and so is
    one set with **auto_disable -u** (unused for): an ACL group does not
    keep its last use.

Attaching and detaching ask before they change anything; the global
option **-f** skips the question.

**add_policy *aclgroup* *policy***  
Attach a policy to the ACL group.  
A policy has a list of object types it is for; one that does not name
**aclgroup** is refused. So is a second policy of a type that allows
only one per object, even when the first one is disabled, and a policy
the ACL group already has.  
Needs the ACL **assign:policy**.

**remove_policy *aclgroup* *policy***  
Remove a policy from the ACL group.  
Needs the ACL **remove:policy**, and that one verbatim: a plain
**remove** does not cover it. Detaching a policy takes away what it
enforces, so it must not be cheaper than attaching one.

**list_policies \[**--return-type** *TYPE*\] \[**--policy-types** *t1,t2*\] *aclgroup***  
List the policies attached to the ACL group, the disabled ones too,
marked **(disabled)**. Use **--return-type** to select the attribute
returned (**name**, **read_oid**, **full_oid**, **uuid**); without it
the names. Only the names are marked. Use **--policy-types** to list
only policies of the given types; these are policy types, not policy
names.  
Needs the ACL **view:policies**.

## ACL Management

An ACL on an ACL group says what somebody may do with the group itself,
not what the group grants. The somebody is a role or a token, never a
user.

What the three forms **acl**, **+acl** and **++acl** mean is under
**ACLs** in **otpme**(7). Tab completion after **add_acl** offers the
ACLs an ACL group knows. An ACL group has no default ACLs, **+acl** and
**++acl** are refused: nothing lies in an ACL group that could get them.

Besides the ACLs every object has, these matter for an ACL group:

> **add:entry, **remove:entry**, **view:entries****  
> Change and see the entries, see **Entries**.
>
> **add:aclgroup, **remove:aclgroup**, **view:aclgroups****  
> Change and see the members, see **Members**.

A change of the entries or members counts on every object the group is
given on, and on every object a group that has it as a member is given
on. So whoever has **add:entry** or **add:aclgroup** on a group can
grant any ACL wherever the group is given; give them with care.

Adding and removing ask first, once for the whole command; the global
option **-f** skips the question.

**add_acl *aclgroup* *owner_type* *owner* *acl*\[:*value*\]\[,*acl*\[:*value*\]\]**  
Give a role or a token one or more ACLs on this ACL group.  
*owner_type* is **role** or **token**. *owner* names it the way
**list_acls** prints it: a role as *site/name*, e.g.
**munich/helpdesk**, or by its name alone on its own site; a token as
*user/token*, e.g. **alice/login**. An ACL can carry a value, for
example **view:entries**. To give several ACLs at once, separate them
with commas: **view:entries,view:aclgroups**.  
Needs the ACL **add:acl**.

**del_acl *aclgroup* *acl*\[,*acl*\]**  
Take those ACLs away again.  
Here an *acl* is the whole entry, owner and all, the way **list_acls**
prints it: **role:munich/helpdesk:view:entries**.  
Needs the ACL **delete:acl**.

**list_acls *aclgroup***  
Show the ACLs that lie on this ACL group, i.e. who may do what with it.
Where it is given is shown by **find_acls**, see **Where It Is
Given**.  
Needs the ACL **view:acl**.

**enable_acl_inheritance *aclgroup***  
Let a move of the ACL group swap its default ACLs: what the old unit
handed down is taken away, and what the new unit hands down is given. It
does not by default; a move then leaves the ACLs of the ACL group as
they are.

Only a move asks this. A new ACL group gets the default ACLs of its
unit, and **add_acl -a** or **-r** on a unit reach it either way. A move
with **--keep-acls** leaves its ACLs alone all the same.

A move by somebody who does not hold **add:acl** and **delete:acl** on
the ACL group leaves its ACLs alone as well, and says so. Otherwise
moving an object into a unit would be a way of handing yourself the
default ACLs of that unit.

Needs the ACL **enable:acl_inheritance**.

**disable_acl_inheritance *aclgroup***  
A move leaves the ACLs of the ACL group as they are again.  
Needs the ACL **disable:acl_inheritance**.

## Configuration

An ACL group has two config parameters, see **CONFIG PARAMETERS**.

**config \[**-d**\] \[**-a**\] *aclgroup* *parameter* \[*value*\]**  
Set a parameter on the ACL group.

**-d**  
Remove the parameter from the ACL group, or with a value only that one
value from a list. It is not set back to a default: what applies
afterwards is what the units or the site say.

**-a**  
Append the value to a parameter that holds a list, instead of replacing
what is there.

Needs the ACL **set:config:\<parameter\>**.

**show_config *aclgroup* \[*parameter*\]**  
The parameters set on the ACL group itself, or only the one named.
Nothing is shown for a parameter that the ACL group gets from a unit or
from the site.  
Needs the ACL **view:config:\<parameter\>**.

**get_config *aclgroup* *parameter***  
What the parameter comes to for the ACL group, once the ACL group, its
units and the site have been looked at. So this answers what applies,
where **show_config** answers what was set here.  
Needs the ACL **view:config:\<parameter\>**.

**description *aclgroup* \[*description*\]**  
Set the description. Without one OTPme asks and offers the current text
for editing.  
Needs the ACL **edit:description**.

**info \[**--language** *LANG*\] *aclgroup* \[*info*\]**  
Set free-form info text. If *info* is omitted, the current info text is
opened in the editor named by the **EDITOR** environment variable.  
Without **--language** the text is the administrator's own note. Nothing
shows the info of an ACL group to a user, so a text for a language stays
a note as well.  
Needs the ACL **edit:info**.

**dump_info \[**--language** *LANG*\] *aclgroup***  
Write one of those texts to stdout. **--language** picks which one;
without it you get the note of the administrator.  
Needs the ACL **view:info**.

## Export and Cleanup

**export \[**--password** *password*\] *aclgroup***  
Write the whole object of the ACL group to stdout, as JSON: its entries,
members, ACLs, policies, config parameters and the rest. **otpme-tool
import** reads it back.  
An ACL group holds no key and no secret, so **--password** has nothing
to encrypt: the output is in clear either way.  
Needs the ACL **export**.

**remove_orphans *aclgroup***  
Remove references to objects that are gone: members of the ACL group
that were deleted, orphan ACLs and policies.  
It asks once for what it found; the global option **-f** skips the
question.  
Needs the ACL **remove:orphans**.

# OPTIONS

Every option belongs to one command and is described with that command
above.

Global options work with every command, see **otpme**(1).

# CONFIG PARAMETERS

Set them with **config**, see **Configuration**. A value is looked up on
the ACL group, then on its unit and the units above it, then on the
site; the first one found counts. A parameter the site names in
**force_site_config_parameters** is taken from the site, whatever the
ACL group or its units say. The full descriptions are in **otpme**(7).

**changelog (bool, default: true)**  
Whether the commands that change the ACL group write an entry into its
changelog, see **Object Changelog**.

**allow_changelog_clearing (bool, default: true)**  
Whether **clear_changelog** is allowed on the ACL group. A value on the
token you are signed in with counts first, see **Object Changelog**.

Set on the site or a unit, not on the ACL group:

**max_aclgroup_name_len (int, default: 64)**  
The longest name an ACL group may get, checked by **add** and
**rename**.

# EXAMPLES

**otpme-aclgroup get_acls USERMANAGER**  
Show what the base group **USERMANAGER** holds.

**otpme-unit add_acl -a -r linux/users role helpdesk @USERMANAGER,++@USERMANAGER**  
Let the role **helpdesk** manage the users of the unit **linux/users**
and of its sub units, and their tokens, those there now and those added
later. **@USERMANAGER** lets it add and delete users in the units,
**++@USERMANAGER** counts on the users and tokens below them.

**otpme-aclgroup add it-user-manager**  
Create an ACL group of your own.

**otpme-aclgroup add_aclgroup it-user-manager USERMANAGER**  
Make **USERMANAGER** a member: **it-user-manager** then grants
everything of **USERMANAGER** as well.

**otpme-aclgroup add_entry it-user-manager user:set_temp_password,token:set_temp_password**  
Add temporary passwords for users and tokens, which **USERMANAGER** does
not have.

**otpme-aclgroup get_acls -r it-user-manager**  
Show its entries and those of its members, each with the group in
brackets.

**otpme-unit add_acl -a -r linux/users role helpdesk @it-user-manager,++@it-user-manager**  
Give it on the unit, in the same way as **USERMANAGER** above.

**otpme-aclgroup auto_disable it-user-manager +30D**  
End the delegation in 30 days: a disabled group grants nothing.

# AUTH ON ACTION HOOKS

An auth on action policy can ask for a login again before these actions.
See **Auth On Action Policy** in **otpme-policy**(1). An aclgroup has
the hooks every object type has, and these:

> add_aclgroup, add_entry, remove_aclgroup, remove_entry.

# FILES

*/var/lib/otpme/tree/*  
The objects of the realm. An ACL group is the directory
*\<name\>.aclgroup* in the directory of its unit, e.g.
*\<realm\>.realm/\<site\>.site/aclgroups.unit/USERMANAGER.aclgroup/*,
with its settings in *object.json*, on the nodes of every site, never on
a host. Change them with the commands above, not in the files.

# SEE ALSO

**otpme**(1), **otpme**(7), **otpme-unit**(1), **otpme-role**(1),
**otpme-user**(1), **otpme-token**(1), **otpme-pass**(1),
**otpme-policy**(1), **otpme-trash**(1), **otpme-tool**(1),
**otpme-shell**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
