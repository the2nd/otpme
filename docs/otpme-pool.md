# NAME

otpme-pool - manage OTPme node pools

# SYNOPSIS

**otpme-pool** *command* \[*options*\] \[*pool*\]

# DESCRIPTION

**otpme-pool** manages node pools in the OTPme system. A pool defines
which nodes are used for a share.

# COMMANDS

## Pool Management

**add *pool***  
Create a new pool.

**del *pool***  
Delete a pool. Asks for confirmation according to the confirmation
policy, and warns about shares that use the pool.

**show \[*pool*\]**  
Display pool information.

<!-- -->

**show_oid \[**--full**\] *pool***  
Show the OID of the pool: **pool\|\<realm\>/\<site\>/\<name\>**. With
**--full** the full OID, which names the unit as well:
**pool\|\<realm\>/\<site\>/\<unit_path\>/\<name\>**.  
Needs the ACL **view_public:object**.

**show_uuid *pool***  
Show the UUID of the pool.  
Needs the ACL **view_public:object**.

<!-- -->

**list \[*regex*\]**  
List pools, optionally filtered by regex pattern.

**enable *pool***  
Enable a disabled pool.

**disable *pool***  
Disable a pool without deleting it.

**rename *pool* *new_name***  
Rename a pool.

**move \[**--keep-acls**\] *pool* *unit***  
Move pool to a different unit.

**touch *pool***  
Re-index the object to fix potential index problems.

**auto_disable *pool* *time***  
Set auto-disable time. It is either a relative time with a leading
**+**, e.g. **+30D**, or an absolute one, e.g. **"09:53 13.06.2023"**.
The units are **s**, **m**, **h**, **D**, **W**, **M** and **Y**, see
**otpme**(7). A relative time counts from when it is set, and again from
when the pool is enabled. **0** removes it. It is refused for an object
the realm or a site comes with, e.g. the admin user; a time set on one
before does nothing.

## Node Management

**add_node *pool* *node***  
Add a node to the pool.

**remove_node *pool* *node***  
Remove a node from the pool.

**list_nodes \[**--return-type** *TYPE*\] *pool***  
List nodes in the pool. Use **--return-type** to select the attribute
returned (**name**, **read_oid**, **full_oid**, **uuid**).

## Policy Management

A *policy* is the name of a policy, not a path. It is looked for in the
site of the pool. Which policies there are, and what each of them does,
is in **otpme-policy**(1).

Attaching and detaching ask before they change anything; the global
option **-f** skips the question.

**add_policy *pool* *policy***  
Attach a policy to the pool.  
A policy has a list of object types it is for; one that does not name
**pool** is refused. So is a second policy of a type that allows only
one per object.  
Needs the ACL **assign:policy**.

**remove_policy *pool* *policy***  
Remove a policy from the pool.  
Needs the ACL **remove:policy**, and that one verbatim: a plain
**remove** does not cover it. Detaching a policy takes away what it
enforces, so it must not be cheaper than attaching one.

**list_policies \[**--return-type** *TYPE*\] \[**--policy-types** *t1,t2*\] *pool***  
List the policies attached to the pool, the disabled ones too, marked
**(disabled)**. Use **--return-type** to select the attribute returned
(**name**, **read_oid**, **full_oid**, **uuid**). Use **--policy-types**
to list only policies of the given types; these are policy types, not
policy names.  
Needs the ACL **view:policies**.

## ACL Management

**add_acl *pool* *owner_type* *owner* *acl***  
Add an access control entry.

**del_acl *pool* *acl***  
Remove an access control entry.

**list_acls *pool***  
Display all ACLs for the pool.

**enable_acl_inheritance *pool***  
Let a move of the pool swap its default ACLs: what the old unit handed
down is taken away, and what the new unit hands down is given. It does
not by default; a move then leaves the ACLs of the pool as they are.

Only a move asks this. A new pool gets the default ACLs of its unit, and
**add_acl -a** or **-r** on a unit reach it either way. A move with
**--keep-acls** leaves its ACLs alone all the same.

A move by somebody who does not hold **add:acl** and **delete:acl** on
the pool leaves its ACLs alone as well, and says so. Otherwise moving an
object into a unit would be a way of handing yourself the default ACLs
of that unit.

Needs the ACL **enable:acl_inheritance**.

**disable_acl_inheritance *pool***  
A move leaves the ACLs of the pool as they are again.  
Needs the ACL **disable:acl_inheritance**.

## Configuration

**description *pool* \[*description*\]**  
Set pool description.

**info \[**--language** *LANG*\] *pool* \[*info*\]**  
Set free-form info text. If *info* is omitted, the current info text is
opened in the editor specified by the **EDITOR** environment variable.

**dump_info \[**--language** *LANG*\] *pool***  
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

**changelog *pool***  
Show the changelog of the pool. Needs the ACL **view:changelog**.

**edit_changelog *pool* *entry_id* *comment***  
Set the comment of that entry, or replace the one it has. Needs the ACL
**edit:changelog**.

**del_changelog *pool* *entry_id***  
Remove the comment of that entry. The entry itself stays, and an entry
without a comment is refused. Needs the ACL **edit:changelog**.

**clear_changelog *pool***  
Remove every entry of the changelog.  
This needs more than the ACL **clear:changelog**: the config parameter
**allow_changelog_clearing** has to allow it (see **otpme**(7)). It is
true by default, but where no value is found at all, clearing is
refused. A value set on the token you are signed in with counts first.
Without one, the value of the object counts, read along its cascade.

## Import/Export

**export \[**--password** *PASS*\] *pool***  
Export pool configuration.

**remove_orphans *pool***  
Remove orphaned object references.

# OPTIONS

## Display Options

**-a**  
Show all pools.

**-z *SIZE***  
Limit output size.

**--fields *FIELD1,FIELD2***  
Display only specified fields.

**--node-limit *N***  
Limit number of nodes shown.

**--token-limit *N***  
Limit number of member tokens shown.

**--role-limit *N***  
Limit number of member roles shown.

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

**--keep-acls**  
Preserve ACLs when moving pool.

**--password *PASS***  
Password for encrypting exports.

Global options are available for all commands. See **otpme**(1) for
details.

# EXAMPLES

**otpme-pool add europe**  
Create a pool

**otpme-pool add_node europe node-eu-1**  
Add a node to the pool

**otpme-pool list_nodes europe**  
List nodes in the pool

# AUTH ON ACTION HOOKS

An auth on action policy can ask for a login again before these actions.
See **Auth On Action Policy** in **otpme-policy**(1). A pool has the
hooks every object type has, and no others.

# FILES

*/var/lib/otpme/*  
OTPme data directory

# SEE ALSO

**otpme**(1), **otpme**(7), **otpme-acls**(7), **otpme-share**(1),
**otpme-node**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
