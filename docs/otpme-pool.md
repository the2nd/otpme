# NAME

otpme-pool - manage pools: named lists of nodes that serve shares

# SYNOPSIS

**otpme-pool** *command* \[*options*\] \[*pool*\]

# DESCRIPTION

**otpme-pool** adds, changes and deletes pools. A pool is a named list
of nodes of one site. Put on a share with **otpme-share add_pool**, its
nodes serve that share, see **otpme-share**(1). Shares are the only
thing pools are for.

So a group of nodes is named once, and a node that is put into the pool
serves all of its shares. A share with neither nodes nor pools is served
by all nodes of its site. A disabled pool and a disabled node serve
nothing.

A new pool goes into the unit **pools**, unless a **defaultunits**
policy names another. Pools are synced to the nodes only; hosts get
none.

# COMMANDS

## Pool Management

**add *pool***  
Add a pool. With a path, e.g. **storage/fast**, it goes into that unit;
else into the unit a **defaultunits** policy names, see
**otpme-policy**(1), or into **pools**. The name is unique in the site.
A new pool has no nodes, see **add_node**.  
Needs **add:pool** on the unit.

**del \[**--no-trash**\] *pool***  
Delete the pool. It goes to the trash, see **otpme-trash**(1);
**--no-trash** deletes it right away.  
You type the name of the pool to confirm; where shares still use it, the
question names them. **-f** asks nothing. A share keeps the pool that is
gone until its **remove_orphans**, and gets no nodes from it, see
**otpme-share**(1).  
Needs **delete:object** on the pool or **delete:pool** on the unit.

**show \[**-a**\] \[**-z** *N*\] \[**--fields** *F1,F2*\] \[**--limit** *N*\] \[**--node-limit** *N*\] \[**--policy-limit** *N*\] \[**--sort-by** *field*\] \[**--reverse**\] \[**--raw**\] \[**--csv**\] \[**--csv-sep** *sep*\] \[*pool*\]**  
Without a pool: a table of all of them, with their unit, status, nodes,
policies, ACL inheritance and description.

**-a**  
Also the pools you may only look at, not just the ones you may change.

**-z *N***  
How many pools to print.

**--fields *F1,F2***  
Print these columns and no others, in the order they are named. A name
with a **+** in front is added to the columns that are shown anyway, and
one with a **-** is left out of them.

**--limit *N***  
How many of each kind to print per pool: nodes, policies.

**--node-limit *N*, **--policy-limit** *N***  
The same for one of them.

**--sort-by *field*, **--reverse****  
Which column to sort by, and the other way round.

**--raw, **--csv**, **--csv-sep** *sep***  
**--raw** leaves the header and the borders out, **--csv** prints one
row per line with **;** between the columns, and **--csv-sep** uses
another separator.

A column you may not see says **-**. With a pool named, this prints the
object itself instead of a table row, one value per line; its nodes need
**view:nodes**. **show** *pool***$** prints that one pool as a table
row. A name that is no pool is a pattern with **\***, not a regex, see
**SELECTING OBJECTS** in **otpme**(1).

**show_oid \[**--full**\] *pool***  
Show the OID of the pool: **pool\|\<realm\>/\<site\>/\<name\>**. With
**--full** the full OID, which names the unit as well:
**pool\|\<realm\>/\<site\>/\<unit_path\>/\<name\>**.  
Needs the ACL **view_public:object**.

**show_uuid *pool***  
Show the UUID of the pool.  
Needs the ACL **view_public:object**.

**list \[**-a**\] \[**--attribute** *attribute*\] \[*pattern*\]**  
List the pool names, and with a pattern only those that match it, see
**SELECTING OBJECTS** in **otpme**(1). You get the pools you may change;
**-a** adds those you may only look at. **--attribute** matches the
pattern against that attribute instead of the name.

**enable *pool***  
**disable *pool***  
Only an enabled pool gives its nodes to the shares it is on. A share
that has pools gets nodes only from them and from its own nodes, so a
share whose only pool is disabled has no node. Tables show the status.  
Needs **enable:object** or **disable:object**.

**rename *pool* *new_name***  
Rename the pool. The new name must not be in use in the site. The shares
keep it: they name it by its UUID.  
Needs **rename:object**.

**move \[**--keep-acls**\] *pool* *unit***  
Move the pool into another unit of its site. The pool keeps its ACLs;
where ACL inheritance is on for it (off for pools by default, see
**enable_acl_inheritance**), the default ACLs of the old unit are taken
away and those of the new one given. **--keep-acls** keeps all ACLs as
they are.  
Needs **move** on the pool and **add:pool** on the unit.

**touch *pool***  
Write the index entries of the pool again.  
Needs **touch**.

**auto_disable *pool* *time***  
Set auto-disable time. It is either a relative time with a leading
**+**, e.g. **+30D**, or an absolute one, e.g. **"09:53 13.06.2023"**.
The units are **s**, **m**, **h**, **D**, **W**, **M** and **Y**, see
**otpme**(7). A relative time counts from when it is set, and again from
when the pool is enabled. **0** removes it.  
Needs **edit:auto_disable**.

## Node Management

The nodes of a pool serve the shares the pool is on, see **add_pool** in
**otpme-share**(1). A node is one of the site of the pool, and a
disabled node serves no share.

Adding and removing ask first; the global option **-f** skips the
question. Each writes an entry to the changelog.

**add_node *pool* *node***  
Put a node into the pool.  
Needs the ACL **add:node**.

**remove_node *pool* *node***  
Take a node out of the pool. A node that was deleted has no name to be
given here: it stays in the pool, serving nothing, until
**remove_orphans** takes it out.  
Needs the ACL **remove:node**.

**list_nodes \[**--return-type** *TYPE*\] *pool***  
List the nodes of the pool, by name. Disabled nodes are not listed.
**--return-type** selects what to print instead (**name**, **read_oid**,
**full_oid**, **uuid**).  
Needs the ACL **view:nodes**.

## Policy Management

A *policy* is the name of a policy, not a path. It is looked for in the
site of the pool. Which policies there are, and what each of them does,
is in **otpme-policy**(1).

Two policy types fit a pool: **authonaction** and **autodisable**.

Attaching and detaching ask before they change anything; the global
option **-f** skips the question.

**add_policy *pool* *policy***  
Attach a policy to the pool.  
A policy has a list of object types it is for; one that does not name
**pool** is refused. So is a second policy of a type that allows only
one per object, even when the first one is disabled, and a policy the
pool already has.  
An auto-disable policy with **-u** is refused, because a pool does not
keep its last use.  
Needs the ACL **assign:policy**.

**remove_policy *pool* *policy***  
Remove a policy from the pool.  
Needs the ACL **remove:policy**, and that one verbatim: a plain
**remove** does not cover it. Detaching a policy takes away what it
enforces, so it must not be cheaper than attaching one.

**list_policies \[**--return-type** *TYPE*\] \[**--policy-types** *t1,t2*\] *pool***  
List the policies attached to the pool, the disabled ones too, marked
**(disabled)**. Use **--return-type** to select the attribute returned
(**name**, **read_oid**, **full_oid**, **uuid**); without it the names.
Only the names are marked. Use **--policy-types** to list only policies
of the given types; these are policy types, not policy names.  
Needs the ACL **view:policies**.

## ACL Management

An ACL says what somebody may do with this pool. The somebody is a role
or a token, never a user.

What the three forms **acl**, **+acl** and **++acl** mean is under
**ACLs** in **otpme**(7). Tab completion after **add_acl** offers the
ACLs a pool knows. A pool has no default ACLs, **+acl** and **++acl**:
nothing lies in a pool that could get them.

Adding and removing ask first; the global option **-f** skips the
question.

**add_acl *pool* *owner_type* *owner* *acl*\[:*value*\]\[,*acl*\[:*value*\]\]**  
Give a role or a token one or more ACLs on this pool.  
*owner_type* is **role** or **token**. *owner* names it the way
**list_acls** prints it: a role as *site/name*, or by its name alone on
its own site; a token as *user/token*. An ACL can carry a value, for
example **view:nodes**. To give several ACLs at once, separate them with
commas: **view:nodes,add:node**.  
Needs the ACL **add:acl**.

**del_acl *pool* *acl*\[,*acl*\]**  
Take those ACLs away again.  
Here an *acl* is the whole entry, owner and all, the way **list_acls**
prints it: **role:berlin/helpdesk:view:nodes**.  
Needs the ACL **delete:acl**.

**list_acls *pool***  
Show the ACLs that lie on this pool, i.e. who may do what with it.  
Needs the ACL **view:acl**.

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

## Pool Configuration

A pool has two config parameters: **changelog** and
**allow_changelog_clearing**, see **CONFIG PARAMETERS**. A parameter is
looked up at the pool, then at each unit above it, then at the site.

**config \[**-d**\] \[**-a**\] *pool* *parameter* \[*value*\]**  
Set a parameter on the pool.

**-d**  
Remove the parameter from the pool, or with a value only that one value
from a list. It is not set back to a default: what applies afterwards is
what a unit above or the site says.

**-a**  
Append the value to a parameter that holds a list, instead of replacing
what is there.

The ACL is per parameter, **set:config:\<parameter\>**.

**show_config *pool* \[*parameter*\]**  
The parameters set on the pool itself, or only the one named. Nothing is
shown for a parameter that the pool gets from a unit or from the site.  
The ACL is per parameter, **view:config:\<parameter\>**. Without one, a
parameter is left out of the list.

**get_config *pool* *parameter***  
What the parameter comes to for the pool, once the pool, the units above
and the site have been looked at. So this answers what applies, where
**show_config** answers what was set here.  
Needs **view:config:\<parameter\>**.

**description *pool* \[*description*\]**  
Set the description. Without one OTPme asks and offers the current text
for editing. Needs **edit:description**.

**info \[**--language** *LANG*\] *pool* \[*info*\]**  
Set free-form info text. If *info* is omitted, the current info text is
opened in the editor named by the **EDITOR** environment variable. Needs
**edit:info**.  
Without **--language** the text is the administrator's own note. Nothing
shows the info of a pool to a user, so a text for a language stays a
note as well.

**dump_info \[**--language** *LANG*\] *pool***  
Write one of those texts to stdout. **--language** picks which one;
without it you get the note of the administrator. Needs **view:info**.

## Object Changelog

Every change to the object writes an entry: who made it, when, and what
was done. A change can carry a comment of its own, through the global
option **--changelog**.

Unless the **changelog** config parameter says otherwise. It is read
along the cascade (pool, unit, site), and nothing is written where it is
off. Without any value anywhere it is on.

An *entry_id* is the number the listing shows in front of an entry,
counted from 0.

Only the comment of an entry can be changed or removed. What was done
and by whom stays as it is.

A command that changes something asks first; the global option **-f**
skips the question.

**changelog *pool***  
Show the changelog of the pool, one entry per line: its *entry_id*, the
time, who made the change and what was done, then a detail in round
brackets and the comment in square brackets where there are any. Needs
the ACL **view:changelog**.

**edit_changelog *pool* *entry_id* *comment***  
Set the comment of that entry, or replace the one it has. That writes an
entry of its own. Needs the ACL **edit:changelog**.

**del_changelog *pool* *entry_id***  
Remove the comment of that entry. The entry itself stays, and an entry
without a comment is refused. That writes an entry of its own. Needs the
ACL **edit:changelog**.

**clear_changelog *pool***  
Remove every entry of the changelog. Afterwards it holds one entry: that
it was cleared.  
This needs more than the ACL **clear:changelog**: the config parameter
**allow_changelog_clearing** has to allow it (see **otpme**(7)). It is
true by default, but where no value is found at all, clearing is
refused. A value set on the token you are signed in with counts first.
Without one, the value of the pool counts, read along its cascade.

## Export and Cleanup

**export \[**--password** *password*\] *pool***  
Write the whole object of the pool to stdout, as JSON: its nodes, ACLs,
policies, config parameters and the rest. **otpme-tool import** reads it
back.  
A pool holds no key and no secret, so **--password** has nothing to
encrypt: the output is in clear either way.  
Needs the ACL **export**.

**remove_orphans *pool***  
Remove references to objects that are gone: nodes of the pool that were
deleted, orphan ACLs and policies.  
It asks once for what it found; the global option **-f** skips the
question.  
Needs the ACL **remove:orphans**.

# OPTIONS

Every option belongs to one command and is described with that command
above.

Global options work with every command, see **otpme**(1).

# CONFIG PARAMETERS

A pool takes these. What each of them does, and how a parameter is
resolved, is in **otpme**(7).

**changelog (bool, default: true)**  
Whether the commands on this pool are written to its changelog.

**allow_changelog_clearing (bool, default: true)**  
Whether that changelog may be cleared.

# EXAMPLES

## Two nodes for a share

**otpme-pool add fileservers**  
The pool goes into the unit **pools**.

**otpme-pool add_node fileservers node1**  
**otpme-pool add_node fileservers node2**  
Both nodes are of the site of the pool.

**otpme-share add_pool data fileservers**  
**node1** and **node2** serve the share **data** now, and so does a node
that is put into the pool later.

**otpme-pool list_nodes fileservers**  
The nodes of the pool; a disabled node is not listed.

## A node out of the pool

**otpme-pool remove_node fileservers node2**  
**node2** no longer serves **data**, unless the share names it itself or
has another pool with it.

## The pool off

**otpme-pool disable fileservers**  
Its nodes serve none of its shares. A share whose only pool this is is
served by no node: it does not fall back to all nodes of the site.

**otpme-share remove_pool data fileservers**  
With no node and no pool left, **data** is served by all nodes of its
site again.

# AUTH ON ACTION HOOKS

An auth on action policy can ask for a login again before these actions.
See **Auth On Action Policy** in **otpme-policy**(1). A pool has the
hooks every object type has, and no others.

# FILES

*/var/lib/otpme/tree/*  
The objects of the realm, on the nodes. Hosts get no pools. A pool is
the directory *\<pool\>.pool* in the directory of its unit, e.g.
*\<realm\>.realm/\<site\>.site/pools.unit/fileservers.pool/*, with its
settings in *object.json*. Change them with the commands above, not in
the file.

# SEE ALSO

**otpme**(1), **otpme**(7), **otpme-share**(1), **otpme-node**(1),
**otpme-unit**(1), **otpme-policy**(1), **otpme-trash**(1),
**otpme-tool**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2026 the2nd. License: GPLv3
