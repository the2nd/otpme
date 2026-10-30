# NAME

otpme-unit - manage units: the folders of a site that hold its objects
and hand ACLs, policies and settings down to them

# SYNOPSIS

**otpme-unit** *command* \[*options*\] \[*unit*\]

# DESCRIPTION

**otpme-unit** adds, moves and deletes units, and sets what they hand
down. A unit is a folder in a site. Almost every object is in one:
users, groups, roles, hosts, nodes, policies and the rest; only realms,
sites and tokens are not, a token is in its user. A unit can hold other
units. It is named by its path in the site, e.g. **linux/users**.

A site comes with one unit per object type, e.g. **users**, **groups**,
**hosts**. These cannot be deleted or moved. Which unit a new object
goes to is said by a **defaultunits** policy, see **otpme-policy**(1).

What a unit sets holds for what is in it:

> -   Default ACLs (**+** and **++**) are given to its objects, see
>     **ACL Management**.
>
> -   A config parameter applies to every object below that sets none of
>     its own, see **CONFIG PARAMETERS**.
>
> -   A **defaultpolicies** policy says which policies a new object
>     gets; on the unit **users**, **defaultgroups** and
>     **defaultroles** say which groups and roles a new user gets.

# COMMANDS

## Unit Management

**add *unit***  
Add a unit. A unit below another one is given as a path, e.g.
**linux/users**; the one above must exist. Needs **add:unit** on the
unit above, or on the site for a unit at the top, and that ACL verbatim:
a plain **add** does not cover it.  
The new unit takes the ACLs of the unit above that belong to your token
or its roles, inherits ACLs, and gets the policies that
**default_policies** names for units, see **otpme-policy**(1).

**del \[**--no-trash**\] *unit***  
Delete the unit with everything in it, the units below included. The
question names what is in it; **-f** does not ask. All of it goes to the
trash as one entry, see **otpme-trash**(1); **--no-trash** deletes right
away.  
If you may not delete one of the objects, nothing is deleted. Needs
**delete:unit** on the unit above, or **delete:object** on the unit. The
units a site comes with cannot be deleted.

**show \[**-a**\] \[**-z** *N*\] \[**--fields** *F1,F2*\] \[**--limit** *N*\] \[**--policy-limit** *N*\] \[**--sort-by** *field*\] \[**--reverse**\] \[**--raw**\] \[**--csv**\] \[**--csv-sep** *sep*\] \[*unit*\]**  
Without a unit: a table of the units, with **unitname**, **status**,
**policies**, **inherit** (ACL inheritance) and **description**.

**-a**  
Also the units you may only look at, not just the ones you may change.

**-z *N***  
How many units to print.

**--fields *F1,F2***  
Print these columns and no others, in the order they are named. A name
with a **+** in front is added to the columns that are shown anyway, and
one with a **-** is left out of them.

**--limit *N*, **--policy-limit** *N***  
How many policies to print per unit.

**--sort-by *field*, **--reverse****  
Which column to sort by, and the other way round.

**--raw, **--csv**, **--csv-sep** *sep***  
**--raw** leaves the header and the borders out, **--csv** prints one
row per line with **;** between the columns, and **--csv-sep** uses
another separator.

With a unit named: what is in it, by type, as far as you may see it.
That needs **view_public:object** on the unit.

<!-- -->

**show_oid \[**--full**\] *unit***  
Show the OID of the unit: **unit\|\<realm\>/\<site\>/\<unit_path\>**.
**--full** is accepted and shows the same.  
Needs the ACL **view_public:object**.

**show_uuid *unit***  
Show the UUID of the unit.  
Needs the ACL **view_public:object**.

<!-- -->

**list \[**-a**\] \[**--attribute** *attribute*\] \[*regex*\]**  
List the unit names, and with a regex only those that match it. You get
the units you may change; **-a** adds those you may only look at.
**--attribute** matches the regex against that attribute instead of the
name.

**enable *unit***  
**disable *unit***  
A user right in a disabled unit cannot log in; admins and users with
**allow_disabled_login** can. Units below are not affected. Tables show
a disabled unit with **(D)**.

**rename *unit* *new_name***  
Not possible; use **move** with the full new path, e.g. **otpme-unit
move linux/users linux/staff**.

**move \[**-m**\] \[**-k**\] \[**-o** *types*\] \[**--keep-acls**\] \[**--skip-ca**\] *unit* *new_unit***  
Move the unit with everything in it. *new_unit* is a path below the
site, not below the unit above. A new unit is made there and takes over
what this one has: ACLs, policies, description, info texts, config
parameters, ACL inheritance, extensions, object classes and attributes.
Everything moves into it, and this one is deleted. What moves along
keeps its ACLs. Where ACL inheritance is on for the unit, the default
ACLs of the old parent are then taken back from it and from everything
in it, and those of the new parent are given, see
**enable_acl_inheritance**. With **-m** nothing is taken over, the unit
there keeps its own. The new unit has a new UUID; a **defaultunits**
policy that named this one names the new one afterwards. Needs **move**
on the unit and **add:unit** where it goes.

**-m**  
Move into a unit that exists. Each object asks its own ACL inheritance
whether it swaps the default ACLs of this unit for those of that one.

**-k**  
Keep this unit, empty.

**-o *types***  
Only these object types, e.g. **user,group**; needs **-k**.

**--keep-acls**  
Keep all ACLs as they are, whatever ACL inheritance says.

**--skip-ca**  
A CA cannot be moved: move everything else and keep this unit. Without
it a unit with a CA is not moved.

**touch *unit***  
Write the index entries of the unit again.

**auto_disable *unit* *time***  
Set auto-disable time. It is either a relative time with a leading
**+**, e.g. **+30D**, or an absolute one, e.g. **"09:53 13.06.2023"**.
The units are **s**, **m**, **h**, **D**, **W**, **M** and **Y**, see
**otpme**(7). A relative time counts from when it is set, and again from
when the unit is enabled. **0** removes it. It is refused for an object
the realm or a site comes with, e.g. the admin user; a time set on one
before does nothing.

## Unit Configuration

A config parameter set on a unit counts for everything in it and below,
down to a unit or object that sets its own. It is looked up at the
object, then at each unit above it, then at the site; a parameter in
**force_site_config_parameters** starts at the site. Which parameters
there are is in **otpme**(7).

**config \[**-d**\] \[**-a**\] *unit* *parameter* \[*value*\]**  
Set a parameter on the unit.

**-d**  
Remove the parameter from the unit, or with a value only that one value
from a list. It is not set back to a default: what applies afterwards is
what a unit above or the site says.

**-a**  
Append the value to a parameter that holds a list, instead of replacing
what is there.

The ACL is per parameter, **set:config:\<parameter\>**.

**show_config *unit* \[*parameter*\]**  
The parameters set on the unit itself, or only the one named. Nothing is
shown for a parameter that the unit gets from a unit above or from the
site.

**get_config *unit* *parameter***  
What the parameter comes to for the unit, once the unit, the units above
and the site have been looked at. So this answers what applies, where
**show_config** answers what was set here.

**description *unit* \[*description*\]**  
Set the description. Without one OTPme asks and offers the current text
for editing. Needs **edit:description**.

**info \[**--language** *LANG*\] *unit* \[*info*\]**  
Set free-form info text. If *info* is omitted, the current info text is
opened in the editor named by the **EDITOR** environment variable. Needs
**edit:info**.  
Without **--language** the text is the administrator's own note. Nothing
shows the info of a unit to a user, so a text for a language stays a
note as well.

**dump_info \[**--language** *LANG*\] *unit***  
Write one of those texts to stdout. **--language** picks which one;
without it you get the note of the administrator. Needs **view:info**.

## Password Members

The config parameter **password_store_members** names who gets the keys
of the passwords below the unit, see **otpme-pass**(1). The members
count only when a user signed them. Without it set on the unit, the
commands below say so.

**sign_password_members *unit***  
Sign the members with your sign key. The signature covers the members
and the users they stand for now.  
It first shows what changed since your last signature, and asks. The
global option **-f** skips the question. When nothing changed, it says
so and signs nothing. The signature is written to the changelog of the
unit.  
Whether a signature counts is decided by each host: only a signer of
type **password** set up there makes it count, see **otpme-tool**(1).  
Needs the ACL **set:config:password_store_members**.

**show_password_members *unit***  
Show the members, the users they stand for, and each signature. A
signature is up to date, or out of date with the users it lacks (**+**)
and the ones it still names (**-**).  
Needs the ACL **view:config:password_store_members**.

**unsign_password_members \[**--signer** *user*\] *unit***  
Remove your signature. With **--signer** the one of that user. For a
user that is gone, give the UUID that **show_password_members** shows.  
It asks first; the global option **-f** skips the question. The members
and the other signatures stay. The removal is written to the changelog
of the unit.  
Needs the ACL **set:config:password_store_members**.

## Object Changelog

Every change to the object writes an entry: who made it, when, and what
was done. A change can carry a comment of its own, through the global
option **--changelog**.

Unless the **changelog** config parameter says otherwise. It is read
along the cascade, and nothing is written where it is off — not for the
unit, and not for the objects below it that do not set it themselves.
Without any value anywhere it is on.

An *entry_id* is the number the listing shows in front of an entry,
counted from 0.

Only the comment of an entry can be changed or removed. What was done
and by whom stays as it is.

A command that changes something asks first; the global option **-f**
skips the question.

**changelog *unit***  
Show the changelog of the unit. Needs the ACL **view:changelog**.

**edit_changelog *unit* *entry_id* *comment***  
Set the comment of that entry, or replace the one it has. Needs the ACL
**edit:changelog**.

**del_changelog *unit* *entry_id***  
Remove the comment of that entry. The entry itself stays, and an entry
without a comment is refused. Needs the ACL **edit:changelog**.

**clear_changelog *unit***  
Remove every entry of the changelog. Afterwards it holds one entry: that
it was cleared.  
This needs more than the ACL **clear:changelog**: the config parameter
**allow_changelog_clearing** has to allow it (see **otpme**(7)). It is
true by default, but where no value is found at all, clearing is
refused. A value set on the token you are signed in with counts first.
Without one, the value of the unit counts, read along its cascade.

## Policy Management

A *policy* is the name of a policy, not a path. It is looked for in the
site of the unit. Which policies there are, and what each of them does,
is in **otpme-policy**(1).

Attaching and detaching ask before they change anything; the global
option **-f** skips the question.

**add_policy *unit* *policy***  
Attach a policy to the unit.  
A policy has a list of object types it is for; one that does not name
**unit** is refused. So is a second policy of a type that allows only
one per object, even when the first one is disabled, and a policy the
unit already has.  
Some types check more. An auto-disable policy with **-u** is refused,
because a unit does not keep its last use. For a default groups, default
roles or default policies policy you need the rights it uses:
**add:token** on its groups and roles, **add:default_group_user** on its
default group, and for each of its policies what attaching that one
needs. See **otpme-policy**(1).  
Needs the ACL **assign:policy**.

**remove_policy *unit* *policy***  
Remove a policy from the unit.  
Needs the ACL **remove:policy**, and that one verbatim: a plain
**remove** does not cover it. Detaching a policy takes away what it
enforces, so it must not be cheaper than attaching one.

**list_policies \[**--return-type** *TYPE*\] \[**--policy-types** *t1,t2*\] *unit***  
List the policies attached to the unit, the disabled ones too, marked
**(disabled)**. Use **--return-type** to select the attribute returned
(**name**, **read_oid**, **full_oid**, **uuid**); without it the names.
Only the names are marked. Use **--policy-types** to list only policies
of the given types; these are policy types, not policy names.  
Needs the ACL **view:policies**.

## ACL Management

An ACL says what somebody may do with this unit. The somebody is a role
or a token, never a user.

A normal ACL is for the unit object alone. A default ACL, **+acl** or
**++acl**, is not for the unit: it is for the objects in it, and a new
object gets it when it is created. What the three forms mean, and which
ACLs exist, is under **ACLs** in **otpme**(7) and in **otpme-acls**(7).

Adding and removing ask first, once for the whole command; the global
option **-f** skips the question.

**add_acl \[**-r**\] \[**-a**\] \[**--objects** *types*\] \[**--procs** *num*\] *unit* *owner_type* *owner* *acl*\[:*value*\]\[,*acl*\[:*value*\]\]**  
Give a role or a token one or more ACLs on this unit.  
*owner_type* is **role** or **token**. *owner* is the path of that role
or token. An ACL can carry a value, for example **view:policies**. To
give several ACLs at once, separate them with commas:
**+user:edit,+user:view**.  
Without an option only the unit is changed. A default ACL then reaches
what is created from now on, and nothing that is already there.

**-a**  
Hand a default ACL down to what is already in the unit: with
**+user:edit** every user in it gets **edit**. It is of no use for a
normal ACL.  
This goes one level deep. For the units below and what is in them, add
**-r**.

**-r**  
Set the ACL, as it is written, on everything below the unit that knows
it: every unit and every object in them, all the way down. So **-r**
with **view** puts **view** on all of them.  
With **-a** it also hands a default ACL down all the way.

**--objects *type1,type2***  
Only touch objects of these types, for example **user,token**.

**--procs *num***  
A run with **-r** or **-a** walks every object of the unit, and with
**-r** of the units below it. Where a unit holds many, its objects are
shared out over several processes, and this says how many. Without it a
quarter of the cores of the node, which leaves the rest for the daemons
that go on serving logins while this runs.

**-a** and **-r** reach every object below, whatever its ACL inheritance
says.  
Needs the ACL **add:acl**.

**del_acl \[**-r**\] \[**-a**\] \[**--objects** *types*\] \[**--procs** *num*\] *unit* *acl*\[,*acl*\]**  
Take those ACLs away again.  
Here an *acl* is the whole entry, owner and all, the way **list_acls**
prints it: **role:berlin/helpdesk:+user:edit**.  
Without an option only the entry on the unit goes, and what was handed
down stays where it is.

**-a**  
Take back what a default ACL handed down: the objects in the unit lose
the ACL it gave them. Removing **+user:edit** this way takes **edit**
from every user in it.  
OTPme does not keep where an ACL came from. If the same role or token
was given **edit** on one of those users by hand, that goes as well.

**-r**  
Remove the ACL, as it is written, from everything below the unit that
has it; with **-a**, take back all the way down.

**--objects, **--procs****  
As with **add_acl**.

Needs the ACL **delete:acl**.

**list_acls *unit***  
Show the ACLs that lie on this unit, i.e. who may do what with it, and
the default ACLs it hands down.  
Needs the ACL **view:acl**.

**enable_acl_inheritance *unit***  
Let a move of the unit swap its default ACLs: what the old parent handed
down is taken back, from the unit and from everything in it, and what
the new parent hands down is given. The parent is the unit above, or the
site. It does not by default; a move then leaves all ACLs as they are.

Only a move asks this. A new unit gets the default ACLs of its parent,
and **add_acl -a** or **-r** above reach it either way. A move with
**--keep-acls** leaves the ACLs alone all the same, and so does a new
name under the same parent.

Below the unit it is the recursive default ACLs of a parent, **++acl**,
that are taken back and given, the way **add_acl -a -r** hands them
down. A default ACL that is not recursive reaches the unit and stops
there. As with **del_acl -a**, an ACL given by hand that is the same as
one handed down goes with it.

A move by somebody who does not hold **add:acl** and **delete:acl** on
the unit leaves its ACLs alone as well, and says so.

Units had it on until config version 2, which switches it off for all of
them (see **upgrade** in **otpme-site**(1)). Until then it did nothing.

Needs the ACL **enable:acl_inheritance**.

**disable_acl_inheritance *unit***  
A move leaves all ACLs as they are again.  
Needs the ACL **disable:acl_inheritance**.

## Extensions and LDAP Attributes

A unit is also an LDAP entry, **ou=***unit* under its parent unit or the
site, for example **ou=users,ou=linux,ou=berlin,dc=example,dc=org**. An
extension is what gives it one: the object classes it is of, and the
attributes those classes allow. What **ldapd** serves and what
**show_ldif** prints comes from them.

A unit has the extension **base**, which makes it an
**organizationalUnit** with **ou** and **description**. The class allows
more, an address or a phone number for example, and those can be set
here. No other extension is for units, and **base** cannot be removed,
because **ou** names the entry.

The commands that change something ask first; the global option **-f**
skips the question.

**add_extension *unit* *extension***  
Add an extension to the unit. One that is not for units is refused, and
so is one the unit already has; for a unit, that is every extension
today.  
Needs the ACL **add:extension**.

**remove_extension *unit* *extension***  
Take it away again, with the classes and attributes it brought. An
extension that brings the attribute naming the entry cannot be removed,
and for a unit that is **base**.  
Needs the ACL **remove:extension**.

**add_attribute *unit* *attribute***=**\[*value*\]**  
Set an LDAP attribute of the unit.

Only an attribute **organizationalUnit** allows. **ou** is read-only: it
is the name of the unit. An attribute can hold more than one value, so
this adds one and leaves the others.

Everything after the first **=** is the value, so a DN works:
**seeAlso=cn=printers,ou=berlin,dc=example,dc=org**. Without a value
OTPme fills in its own where it has one: for **description**, the
description of the unit.

The ACL is per attribute, **add:attribute:***attribute*, and a plain
**add:attribute** covers all of them.

**modify_attribute *unit* *attribute* *old_value* *new_value***  
Put *new_value* in the place of *old_value*, and leave the other values
of the attribute alone. An *old_value* the unit does not have is an
error.  
The ACL is **edit:attribute:***attribute*.

**del_attribute *unit* *attribute***=**\[*value*\]**  
Remove that value, or the whole attribute where no value is given.
**ou** cannot be removed.  
The ACL is **delete:attribute:***attribute*.

**add_object_class *unit* *class***  
Add an LDAP object class. Only a class an extension of the unit knows is
taken, and for a unit that is **organizationalUnit**, which it has
already.  
Needs the ACL **add:object_class**.

**del_object_class *unit* *class***  
Remove an object class again, with the attributes only it allows. The
class that allows the attribute naming the entry stays, unless another
class of the unit allows it too. For a unit that is
**organizationalUnit**, its only class.  
Needs the ACL **delete:object_class**.

**show_ldif *unit* \[**-a** *attribute1,attribute2*\]**  
The unit as LDAP sees it. **-a** prints only those attributes.

## Export and Cleanup

**export \[**--password** *password*\] *unit***  
Write the whole object of the unit to stdout, as JSON: its ACLs,
policies, config parameters, LDAP attributes and the rest, but not the
objects in it. **otpme-tool import** reads it back.  
A unit holds no key and no secret, so **--password** has nothing to
encrypt: the output is in clear either way.  
Needs the ACL **export**.

**remove_orphans \[**-r**\] *unit***  
Remove references to objects that are gone: orphan ACLs, policies and
signatures of the unit.  
**-r** goes on through the objects in the unit and in its units below,
and cleans those up as well. An object with nothing to clean up says
nothing; one without the ACL is skipped with “Permission denied”.  
It asks once for what it found on an object; the global option **-f**
skips the question.  
Needs the ACL **remove:orphans**.

# OPTIONS

Every option belongs to one command and is described with that command
above.

Global options work with every command, see **otpme**(1).

# CONFIG PARAMETERS

A unit takes the config parameters a site takes, except the ones for the
site alone, such as **force_site_config_parameters**, the trusts and the
settings of the SSO portal. Which there are, and what each of them does,
is in **otpme**(7); its line *Object types* says where each one can be
set.

A new unit has none of them set. Until one is set on it, the units above
and the site decide for it and for everything in it, see **Unit
Configuration**. **show_config** *unit* prints the ones set on the unit,
**get_config** what applies.

A limit set on a unit counts for what is created in it: with
**max_unit_name_len** 16 on **linux**, no unit below **linux** gets a
longer name.

# EXAMPLES

## A unit for the Linux users

**otpme-unit add linux**  
**otpme-unit add linux/users**  
The unit **linux**, and **users** below it.

**otpme-user move alice linux/users**  
**alice** goes there. New users go there when a **defaultunits** policy
names the unit, see **otpme-policy**(1).

## A helpdesk for the users of a unit

**otpme-unit add_acl -r -a linux role helpdesk "++user:edit"**  
The role may change every user in **linux** and in the units below it,
the ones that are there and the ones that come later.

**otpme-unit add_acl -r -a linux role helpdesk @usermanager,++@usermanager**  
The same with the ACL group **usermanager**: the role may add, change
and delete the users and add their tokens, see **otpme-aclgroup**(1). A
change of the group counts at once, without another **add_acl**.

## Putting two units together

**otpme-unit move -m linux/staff linux/users**  
Everything in **linux/staff** goes into **linux/users**, which exists
already. **linux/staff** is deleted.

**otpme-unit move -m -k -o user linux/staff linux/users**  
Only the users go; **linux/staff** stays, with the rest.

## A setting for everything in a unit

**otpme-unit config linux confirmation_policy normal**  
Below **linux** OTPme asks only before a delete, unless a unit below or
the object sets its own.

**otpme-unit get_config linux/users confirmation_policy**  
What applies in **linux/users**: **normal**, from **linux**.

# AUTH ON ACTION HOOKS

An auth on action policy can ask for a login again before these actions.
See **Auth On Action Policy** in **otpme-policy**(1). A unit has the
hooks every object type has, and these:

> set_config_parameter.

It also has **pre_add\_\<type\>** before an object of that type is added
below the unit, and **post_add\_\<type\>** after it, e.g.
**pre_add_user**. *\<type\>* is one of:

> accessgroup, aclgroup, ca, client, device, dictionary, group, host,
> node, pass, policy, pool, resolver, role, scope, script, share, unit,
> user, vlan.

# FILES

*/var/lib/otpme/tree/*  
The objects of the realm, on the nodes and, by sync, on the hosts. A
unit is the directory *\<unit\>.unit* in the directory of its site, or
of the unit above it, e.g.
*\<realm\>.realm/\<site\>.site/linux.unit/users.unit/*, with its
settings in *object.json*. The objects of the unit are in it as
*\<name\>.\<type\>*. Change them with the commands above, not in the
files.

# SEE ALSO

**otpme**(1), **otpme**(7), **otpme-acls**(7), **otpme-site**(1),
**otpme-policy**(1), **otpme-user**(1), **otpme-pass**(1),
**otpme-trash**(1), **otpme-tool**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
