# NAME

otpme-pass - manage passwords

# SYNOPSIS

**otpme-pass** *command* \[*options*\] \[*password*\]

# DESCRIPTION

**otpme-pass** keeps passwords in OTPme, for example the iDRAC and root
passwords of a server.

A password object holds one or more entries. Each entry has a name, a
username, a password, a URL and notes. So the object **server1** can
hold the entries **idrac** and **root**.

The entries are encrypted on the client, the host you work on. The nodes
only store what they cannot read. Entry names, usernames, URLs, notes
and passwords never leave the client unencrypted. What the nodes see in
clear text is the name of the object, its unit, its description and
info, the objects it belongs to, and which users hold a key, as well as
its ACLs, policies, config parameters and changelog. None of these name
an entry.

Every password object has a key of its own. That key is stored once for
every user who may read the password, encrypted with the encrypt public
key of that user. To read a password, the key script of the user
decrypts this key, with the private key of the user (see **key_script**
in **otpme-user**(1)).

What opens or writes the entries runs on hosts only: **add** with an
entry, **change_entry**, **del_entry**, **show_password**,
**list_entries**, **update_keys**, **--offline**, and **show_password**
of **otpme-node** and the others. On a node they refuse: a node holds
the tree, and the passwords would be in clear there. The other commands
work on a node as well.

A name alone puts a new password into the unit a **defaultunits** policy
names, see **otpme-policy**(1), else into **passwords**. A path such as
**passwords/servers/server1** puts it into that unit. Any unit will do;
**passwords** is only where they go by default. Password objects are
synced to the nodes of their own site only, never to hosts and never to
other sites. Nor is the unit **passwords** with everything below it;
another unit with passwords in it is synced, the passwords are not. What
a host keeps, **otpme-agent** fetches, see **Offline use**.

## Who gets a key

The config parameter **password_store_members** of a unit or site names
the members: tokens and roles. A token stands for its owner. A role
stands for the owners of its tokens, and of the tokens of the roles in
it. The nearest unit that sets the parameter counts, else the site.

The members must be signed. A user signs them with **otpme-unit
sign_password_members** (or **otpme-site**). The signature covers the
members and the users they stand for at that moment.

The client checks the signatures, not the nodes. It trusts only signers
of type **password** that are set up on the host:

> **otpme-tool add_signer --signer-type password
> 'user\|example.org/alice'**

Without such a signer, or without a valid signature, nothing is
encrypted. So whoever runs a node cannot add themselves to the members.

A key goes only to users that a valid signature names and that are still
members. When the members change, the signature is out of date:

-   A user who joins gets no key until the members are signed again.

-   A user who leaves loses the key with the next **update_keys**.

A user without an encrypt public key gets no key. OTPme says so.

With **PIN_USER_KEYS** in **otpme.conf**(5), the host also checks the
encrypt public key of each member against the one written down on the
host.

## Who may do what

ACLs decide what a user may do with a password object. The key decides
whether the user can read it. Both are needed.

**view:entries** allows **show_password** and **list_entries**.
**add:entry, **edit:entry**** and **delete:entry** allow changes to
entries. **edit:keys** allows **update_keys**. Tab completion after
**add_acl** offers all ACLs of a password object.

The unit **passwords** gets no ACLs from its site. Give them by hand.
Recursive ACLs of the site do not reach password objects either. Who may
see a password is said on its unit, and on nothing above it. The usual
ACLs are in the base ACL group **PASSUSER**, see **ACL Management**.

## Passwords of other objects

A password can belong to nodes, hosts, devices and clients, for example
the iDRAC password of a node. Add it with **--node** and the others, or
later with **add_node** and the others.

Then **otpme-node show_password** *node* \[*entry*\] shows the passwords
of that node, and the same for hosts, devices and clients. Each password
decides with its own **view:entries** whether it is shown.

When such an object is deleted, its passwords stay. The delete question
says how many there are.

## Offline use

A host can keep passwords, so that they can be read when no node can be
reached.

The config parameter **password_offline_cache** of a unit or site names
the hosts that may keep the passwords below it. It takes hosts, groups
and roles of the site, as OIDs:

>     host|example.org/host1
>     group|example.org/admins
>     role|example.org/berlin/servers

A name without a type is a host. A group or role stands for the hosts in
it, and the hosts of its roles. One that is disabled stands for no host.

The nearest unit that sets it counts, else the site. An empty value on a
unit keeps its passwords off every host:

> **otpme-unit config passwords/servers password_offline_cache ""**

Removing the last entry with **-d** leaves the value empty as well.
**-d** without a value removes the parameter, and the unit above counts
again. Without the parameter anywhere, no host keeps anything.

**otpme-agent** fetches the passwords for the user who is logged in: at
login, every **AGENT_PASS_CACHE_INTERVAL** seconds (see
**otpme.conf**(5)), and when a password or **password_offline_cache**
changes. A host that joins or leaves a group or role is seen at the next
interval. A host keeps only what the user may read: the passwords with
**view:entries** and a key for that user. It keeps them as they are
stored, encrypted. The file stays after logout.

A user whose private key is kept on the server (**key_mode server**)
gets nothing to keep. Reading needs the key script on the host, and the
login leaves it there.

When no node can be reached, **show**, **list**, **list_entries** and
**show_password** read what the host keeps. With **--offline** they read
it without asking a node. Both say on stderr how old the kept passwords
are. Nothing can be changed offline.

Offline, **show** has fewer columns: Password, Unit, Nodes, Hosts,
Devices, Clients and Description.

# COMMANDS

## Password Management

**add \[**--node** *node*\] \[**--host** *host*\] \[**--device** *device*\] \[**--client** *client*\] \[**--username** *username*\] \[**--url** *url*\] \[**--notes** *notes*\] *password* \[*entry*\]**  
Add a password object. With a path, e.g. **passwords/servers/server1**,
it goes into that unit; else into the unit a **defaultunits** policy
names, see **otpme-policy**(1), or into **passwords**. The name is
unique in the site, whatever unit it is in, and is taken in lower case.
It may be **max_pass_name_len** long (64 by default).  
With *entry* the first entry is added as well: the password is asked for
twice, and **--username**, **--url** and **--notes** fill the other
fields, see **Entries**. **--node**, **--host**, **--device** and
**--client** name an object the password belongs to, see **Passwords of
other objects** above.  
When the password object is there already, **add** adds the *entry* to
it, and needs **add:entry**; without an *entry* it says "Password
already exists". **--node** and the others are refused then: use
**add_node** and the others, see **Objects**.  
Needs **add:pass** on the unit.

**del \[**--no-trash**\] *password***  
Delete the password object. It goes to the trash, see
**otpme-trash**(1); **--no-trash** deletes it right away. The hosts that
keep it are told, and drop it.  
Needs **delete:object** on the password or **delete:pass** on the unit.

**show \[**--offline**\] \[**-a**\] \[**-z** *N*\] \[**--fields** *F1,F2*\] \[**--limit** *N*\] \[**--policy-limit** *N*\] \[**--sort-by** *field*\] \[**--reverse**\] \[**--raw**\] \[**--csv**\] \[**--csv-sep** *sep*\] \[*password*\]**  
Without a password: a table of all of them, with their unit, the nodes,
hosts, devices and clients they belong to, policies, ACL inheritance and
description. The entries are not in it, see **show_password**.

**--offline**  
The passwords kept on this host, without asking a node, see **Offline
use** above.

**-a**  
Also the passwords you may only look at, not just the ones you may
change.

**-z *N***  
How many passwords to print.

**--fields *F1,F2***  
Print these columns and no others, in the order they are named. A name
with a **+** in front is added to the columns that are shown anyway, and
one with a **-** is left out of them.

**--limit *N***  
How many of each kind to print per password: nodes, hosts, devices,
clients, policies.

**--policy-limit *N***  
The same for the policies only.

**--sort-by *field*, **--reverse****  
Which column to sort by, and the other way round.

**--raw, **--csv**, **--csv-sep** *sep***  
**--raw** leaves the header and the borders out, **--csv** prints one
row per line with **;** between the columns, and **--csv-sep** uses
another separator.

A column you may not see says **-**. With a password named, this prints
the object itself instead of a table row, one value per line, e.g.
**NODES**; that needs **view_public:object**. **show** *password***$**
prints that one password as a table row. A name that is no password is a
pattern with **\***, not a regex, and a unit path that ends with **/**
shows the passwords of that unit, see **SELECTING OBJECTS** in
**otpme**(1).

**show_oid \[**--full**\] *password***  
Show the OID of the password: **pass\|\<realm\>/\<site\>/\<name\>**.
With **--full** the full OID, which names the unit as well:
**pass\|\<realm\>/\<site\>/\<unit_path\>/\<name\>**.  
Needs the ACL **view_public:object**.

**show_uuid *password***  
Show the UUID of the password.  
Needs the ACL **view_public:object**.

**list \[**--offline**\] \[**-a**\] \[**--attribute** *attribute*\] \[*pattern*\]**  
List the password names, and with a pattern only those that match it,
e.g. **server\***. You get the passwords you may change; **-a** adds
those you may only look at. **--attribute** matches the pattern against
that attribute instead of the name. With **--offline** the passwords
kept on this host are searched the same way.

**rename *password* *new_name***  
Rename the password object. The new name must not be in use in the site,
and is taken in lower case.  
Needs **rename:object**.

**move \[**--keep-acls**\] *password* *unit***  
Move the password object into another unit. ACL inheritance is on for
passwords, see **enable_acl_inheritance**: the default ACLs of the old
unit are taken away and those of the new one given. **--keep-acls**
keeps all ACLs as they are.  
The members of the new unit count from then on, see **Who gets a key**
above. Run **update_keys** when they differ.  
Needs **move** on the password and **add:pass** on the unit.

**touch *password***  
Write the index entries of the password again; the hosts that keep it
fetch it anew.  
Needs **touch**.

## Entries

An entry is added with **add**, see above. Only the client sees the
entries: it opens them with the key of the user, see DESCRIPTION.

A change writes all entries again. So it needs a key as well, like
reading, unless the password has no entries yet, and members with a
valid signature, see **Who gets a key** above. Members that have no key
yet get one with the change; one who left keeps it until
**update_keys**.

**show_password \[**--offline**\] *password* \[*entry*\]**  
Print the entries with their passwords, or only *entry*:

    server1/idrac
        username: root
        password: ...
        url: https://idrac.example.org
        notes:

**--offline** reads what this host keeps, see **Offline use** above.
Online, each call is written to the audit log.  
Needs **view:entries** and a key.

**list_entries \[**--offline**\] *password***  
The same without the passwords.  
Needs **view:entries** and a key.

**change_entry \[**--username** *username*\] \[**--url** *url*\] \[**--notes** *notes*\] \[**--password**\] *password* *entry***  
Change the fields given; an empty value, e.g. **--notes ""**, clears
one. **--password** asks for a new password, twice. Without any of them,
nothing is changed and it says so.  
Needs **edit:entry** and a key.

**del_entry *password* *entry***  
Delete the entry.  
Needs **delete:entry** and a key.

## Keys

**update_keys *password* \| **--all** \[**--unit** *unit*\]**  
Bring the keys of the password in line with its members, see **Who gets
a key** above: members that have no key get one, and users that are no
longer members lose it. Run it after the members were signed again,
after a user left, and after **move**.

When a user lost the key, the client makes a new key and encrypts all
entries with it, so a key kept from before opens nothing written from
then on. What that user read before, they may still know: change those
passwords.

**--all** does every password of this site you may give keys of, one by
one; the others are left out. **--unit** limits that to one unit and the
units below it. At the end it says how many were done, and names the
ones that failed. **--all** and **--unit** are refused together with a
*password*.  
Needs **edit:keys**, and a key yourself, unless the password has no keys
yet.

## Objects

Which nodes, hosts, devices and clients a password belongs to, see
**Passwords of other objects** above. Nothing is needed on the object
itself, only the ACL on the password. When the object is deleted, the
password keeps its UUID until **remove_orphans**.

**add_node *password* *node***  
**remove_node *password* *node***  
The password belongs to this node of the site, or no longer.  
Needs **add:node** or **remove:node**.

**add_host *password* *host***  
**remove_host *password* *host***  
The password belongs to this host, of any site of the realm, or no
longer. **remove_host** also takes the UUID of a host that is gone.  
Needs **add:host** or **remove:host**.

**add_device *password* *device***  
**remove_device *password* *device***  
The password belongs to this device of the realm, or no longer.  
Needs **add:device** or **remove:device**.

**add_client *password* *client***  
**remove_client *password* *client***  
The password belongs to this client of the site, or no longer.  
Needs **add:client** or **remove:client**.

## Object Changelog

Every change to the object writes an entry: who made it, when, and what
was done. A change can carry a comment of its own, through the global
option **--changelog**.

For the entries of a password it says "add entry", "change entry" or
"delete entry", never which one: the name stays on the client, like the
rest of the entry. Reading them is not a change; **show_password** goes
to the audit log instead.

The **changelog** config parameter can switch that off. It is read along
the cascade of the password, and nothing is written where it is off —
not for that password, and not for the ones below a unit that switched
it off. Without any value anywhere it is on.

An *entry_id* is the number the listing shows in front of an entry,
counted from 0.

Only the comment of an entry can be changed or removed. What was done
and by whom stays as it is.

A command that changes something asks first; the global option **-f**
skips the question.

**changelog *password***  
Show the changelog of the password object, one entry per line: its
*entry_id*, the time, who made the change and what was done, then a
detail in round brackets and the comment in square brackets where there
are any.  
Needs the ACL **view:changelog**.

**edit_changelog *password* *entry_id* *comment***  
Set the comment of that entry, or replace the one it has. That writes an
entry of its own.  
Needs the ACL **edit:changelog**.

**del_changelog *password* *entry_id***  
Remove the comment of that entry. The entry itself stays, and an entry
without a comment is refused. That writes an entry of its own.  
Needs the ACL **edit:changelog**.

**clear_changelog *password***  
Remove every entry of the changelog. Afterwards it holds one entry: that
it was cleared.  
This needs more than the ACL **clear:changelog**: the config parameter
**allow_changelog_clearing** has to allow it (see **otpme**(7)). It is
true by default, but where no value is found at all, clearing is
refused. A value set on the token you are signed in with counts first.
Without one, the value of the object counts, read along its cascade.

## Policy Management

A *policy* is the name of a policy, not a path. It is looked for in the
site of the password. Which policies there are, and what each of them
does, is in **otpme-policy**(1).

One type does something on a password: **authonaction** asks whoever
changes the password to authenticate for it again, see **AUTH ON ACTION
HOOKS** below. Every other type is refused.

Reading the entries has no hook: **--offline** reads what the host keeps
without asking a node, so a policy could not stop it. What guards the
entries is the key of the user, e.g. on a YubiKey.

Attaching and detaching ask before they change anything; the global
option **-f** skips the question.

**add_policy *password* *policy***  
Attach a policy to the password object.  
A policy has a list of object types it is for; one that does not name
**pass** is refused. So is a second policy of a type that allows only
one per object.  
Needs the ACL **assign:policy**.

**remove_policy *password* *policy***  
Remove a policy from the password object.  
Needs the ACL **remove:policy**, and that one verbatim: a plain
**remove** does not cover it. Detaching a policy takes away what it
enforces, so it must not be cheaper than attaching one.

**list_policies \[**--return-type** *TYPE*\] \[**--policy-types** *t1,t2*\] *password***  
List the policies attached to the password object, the disabled ones
too, marked **(disabled)**. Use **--return-type** to select the
attribute returned (**name**, **read_oid**, **full_oid**, **uuid**). Use
**--policy-types** to list only policies of the given types; these are
policy types, not policy names.  
Needs the ACL **view:policies**.

## ACL Management

An ACL says what somebody may do with this password object. The somebody
is a role or a token, never a user.

What the three forms **acl**, **+acl** and **++acl** mean is under
**ACLs** in **otpme**(7). Tab completion after **add_acl** offers all
ACLs of a password object.

The usual ACLs for working with the passwords of a unit are in the base
ACL group **PASSUSER**, see **otpme-aclgroup**(1). Give it on the unit
as **@PASSUSER,+@PASSUSER**: **@PASSUSER** lets the owner add and delete
passwords in the unit, **+@PASSUSER** work with the passwords in it.
**++@PASSUSER** reaches the passwords in the sub units as well. Moving,
policies and ACLs are not in it.

A command that changes something asks first; the global option **-f**
skips the question.

**add_acl *password* *owner_type* *owner* *acl*\[:*value*\]\[,*acl*\[:*value*\]\]**  
Give a role or a token one or more ACLs on this password object.  
*owner_type* is **role** or **token**. *owner* names it the way
**list_acls** prints it: a role as *site/name*, or by its name alone on
its own site; a token as *user/token*. An ACL can carry a value, for
example **view:entries**. To give several ACLs at once, separate them
with commas: **view:entries,edit:entry**.  
Needs the ACL **add:acl**.

**del_acl *password* *acl*\[,*acl*\]**  
Take those ACLs away again.  
Here an *acl* is the whole entry, owner and all, the way **list_acls**
prints it: **role:berlin/helpdesk:view:entries**.  
Needs the ACL **delete:acl**.

**list_acls *password***  
Show the ACLs that lie on this password object, i.e. who may do what
with it.  
Needs the ACL **view:acl**.

**enable_acl_inheritance *password***  
Let a move of the password swap its default ACLs: what the old unit
handed down is taken away, and what the new unit hands down is given. It
does by default, because who may see a password is said on its unit.

Only a move asks this. A new password gets the default ACLs of its unit,
and **add_acl -a** or **-r** on a unit reach it either way. A move with
**--keep-acls** leaves its ACLs alone all the same.

A move by somebody who does not hold **add:acl** and **delete:acl** on
the password leaves its ACLs alone as well, and says so. Otherwise
moving a password into a unit would be a way of handing yourself the
default ACLs of that unit.

Needs the ACL **enable:acl_inheritance**.

**disable_acl_inheritance *password***  
A move leaves the ACLs of the password as they are: whoever could reach
it in the old unit still can, and the new unit gives nobody anything.  
Needs the ACL **disable:acl_inheritance**.

## Configuration

**config** sets the parameters every object has; for a password these
are **changelog** and **allow_changelog_clearing**, see **Object
Changelog**.

A command that changes something asks first; the global option **-f**
skips the question.

**config \[**-a**\] \[**-d**\] *password* *parameter* \[*value*\]**  
Set a parameter on the password object.

**-d**  
Remove the parameter from the password object, or with a value only that
one value from a list. It is not set back to a default: what applies
afterwards is whatever the unit or the site says.

**-a**  
Append the value to a parameter that holds a list, instead of replacing
what is there.

The ACL is per parameter, **set:config:\<parameter\>**.

**get_config *password* *parameter***  
What the parameter comes to for this password object, once the object,
its units and its site have been looked at. So this answers what
applies, where **show_config** answers what was set here.  
Needs the ACL **view:config:\<parameter\>**.

**show_config *password* \[*parameter*\]**  
The parameters set on the password object itself, or only the one named.
Nothing is shown for a parameter that it gets from a unit or from the
site.  
Needs the ACL **view:config:\<parameter\>**; without it a parameter is
left out of the list, and one named is refused.

**description *password* \[*description*\]**  
Set the description. Without one OTPme asks and offers the current text
for editing. It is not encrypted: **show** lists it, and a host keeps it
for **--offline**.  
Needs the ACL **edit:description**.

**info \[**--language** *LANG*\] *password* \[*info*\]**  
Set free-form info text. It is not encrypted. If *info* is omitted, the
current info text is opened in the editor named by the **EDITOR**
environment variable (default: vim).  
Needs the ACL **edit:info**.  
Without **--language** the text is the administrator's own note. Nothing
shows the info of a password to a user, so a text for a language stays a
note as well.

**dump_info \[**--language** *LANG*\] *password***  
Write one of those texts to stdout. **--language** picks which one;
without it you get the note of the administrator.  
Needs the ACL **view:info**.

## Export and Cleanup

There is no import on this page: reading an export back in is
**otpme-tool import**, see **otpme-tool**(1).

**remove_orphans** asks before it changes anything; the global option
**-f** skips the question.

**export \[**--password** *passphrase*\] *password***  
Write the whole password object to stdout, as JSON.

Without **--password** it is written as it is, in clear. With one, a key
is derived from that passphrase and the object is encrypted with it; the
salt goes into the output, so the passphrase is all you need to read it
back.

The entries stay encrypted either way: only a user with a key of the
password can read them, as with **show_password**.

The nodes, hosts, devices and clients of the password and the users with
a key are named by UUID, so an export says something only in the realm
it came from.

Needs the ACL **export**.

**remove_orphans *password***  
Remove what the password object still points at although it is gone.

That is its ACLs and its policies, the nodes, hosts, devices and clients
it belongs to, and the keys of users that are gone.

It shows everything it found and asks once for all of it. It asks
nothing and changes nothing when it finds nothing.

Needs the ACL **remove:orphans**.

# OPTIONS

Every option belongs to one command and is described with that command
above.

Global options work with every command, see **otpme**(1).

# EXAMPLES

## Who gets the keys

**otpme-unit config passwords password_store_members 'role\|example.org/berlin/admins'**  
The users of the role **admins** get the keys of the passwords in the
unit **passwords**.

**otpme-unit sign_password_members passwords**  
A user signs the members. Until then nobody gets a key.

**otpme-tool add_signer --signer-type password 'user\|example.org/alice'**  
On each host, as root: trust the signatures of **alice**.

## A password for a node

**otpme-pass add --node node1 --username root --url https://node1-idrac.example.org node1 idrac**  
The password **node1** with its first entry **idrac**, for the node
**node1**. The password of the entry is asked for twice.

**otpme-pass show_password node1 idrac**  
The entry **idrac** with its password.

**otpme-node show_password node1**  
All passwords of the node **node1**.

**otpme-pass change_entry --password node1 idrac**  
A new password for the entry.

## Passwords in a unit of their own

**otpme-unit add passwords/servers**  
**otpme-pass add passwords/servers/server1 root**  
The unit **passwords/servers**, and the password **server1** in it with
the entry **root**.

**otpme-pass update_keys --all --unit passwords/servers**  
Bring the keys of all passwords below **passwords/servers** in line with
the members, e.g. after a user has left.

## Offline use

**otpme-unit config passwords password_offline_cache 'host\|example.org/host1,host\|example.org/host2'**  
The hosts **host1** and **host2** keep the passwords of the unit
**passwords** for offline use.

**otpme-unit config -a passwords password_offline_cache 'group\|example.org/admins'**  
The hosts in the group **admins** keep them as well.

**otpme-pass show_password --offline node1**  
Read the password **node1** from what this host keeps, without asking a
node.

# AUTH ON ACTION HOOKS

An auth on action policy can ask for a login again before these actions.
See **Auth On Action Policy** in **otpme-policy**(1). A pass has the
hooks every object type has, and these; a command of another name is in
brackets:

> add_client, add_device, add_entry (add), add_host, add_node,
> change_entry, del_entry, remove_client, remove_device, remove_host,
> remove_node, update_keys.

# FILES

*/var/lib/otpme/tree/*  
The objects of the realm. A password is the directory *\<name\>.pass* in
the directory of its unit, e.g.
*\<realm\>.realm/\<site\>.site/passwords.unit/node1.pass/*, with its
settings in *object.json*, on the nodes of its site only, never on a
host. Change them with the commands above, not in the files.

*/var/cache/otpme/offline/\<user_uuid\>/pass.json*  
The passwords a host keeps for the user, see **Offline use**. The
directory is *offline* below **CACHE_DIR** in **otpme.conf**(5).
**otpme-agent** writes it for the user, readable by the user alone, and
replaces it as a whole on every fetch. The entries in it stay encrypted;
the names, units, descriptions and the objects the passwords belong to
are in clear.

# SEE ALSO

**otpme**(1), **otpme**(7), **otpme.conf**(5), **otpme-unit**(1),
**otpme-site**(1), **otpme-policy**(1), **otpme-aclgroup**(1),
**otpme-tool**(1), **otpme-user**(1), **otpme-node**(1),
**otpme-host**(1), **otpme-device**(1), **otpme-client**(1),
**otpme-trash**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2026 the2nd. License: GPLv3
