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
clear text is the name of the object, its unit, and the objects it
belongs to.

Every password object has a key of its own. That key is stored once for
every user who may read the password, encrypted with the encrypt public
key of that user. To read a password, the key script of the user
decrypts this key, with the private key of the user (see **key_script**
in **otpme-user**(1)).

**otpme-pass** works on hosts only. On a node it refuses: the passwords
are opened where the user sits.

Password objects live in the unit **passwords** and the units below it.
A name alone puts a new password into **passwords**. A path such as
**passwords/servers/server1** puts it into another unit. Password
objects are synced to the nodes of their own site only, never to hosts
and never to other sites.

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
> 'user\|example.org/berlin/alice'**

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
entries. **edit:keys** allows **update_keys**. All ACLs of a password
object are listed in **otpme-acls**(7).

The unit **passwords** gets no ACLs from its site. Give them by hand.
Recursive ACLs of the site do not reach password objects either. Who may
see a password is said on its unit, and on nothing above it.

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
Add a password object. With *entry* its first entry is added as well,
and the password is asked for twice.  
When the object is there already, **add** adds the *entry* to it. Needs
**add:entry** then.  
**--node**, **--host**, **--device** and **--client** name an object the
password belongs to.

**del \[**--no-trash**\] *password***  
Delete a password object. It goes to the trash unless **--no-trash** is
given.

**show \[**--offline**\] \[*password*\]**  
Show password objects, without their entries. A name can hold **\***,
and a unit path that ends with **/** shows the passwords of that unit.

**list \[**--offline**\] \[**--attribute** *attribute*\] \[**-a**\] \[*regex*\]**  
List password objects.

**rename *password* *new_name***  
Rename a password object.

**move \[**--keep-acls**\] *password* *unit***  
Move a password object to another unit. The members of the new unit
count from then on. Run **update_keys** when they differ.

**touch *password***  
Write the object again, for example to build its index again.

## Entries

**show_password \[**--offline**\] *password* \[*entry*\]**  
Show the entries with their passwords. Without *entry* all entries are
shown.  
Needs **view:entries** and a key.

**list_entries \[**--offline**\] *password***  
Show the entries without their passwords.  
Needs **view:entries** and a key.

**change_entry \[**--username** *username*\] \[**--url** *url*\] \[**--notes** *notes*\] \[**--password**\] *password* *entry***  
Change an entry. **--password** asks for a new password.  
Needs **edit:entry**.

**del_entry *password* *entry***  
Delete an entry.  
Needs **delete:entry**.

## Keys

**update_keys *password* \| **--all** \[**--unit** *unit*\]**  
Give the key to the members that have none, and take it from the users
that are no longer members. Run it after the members were signed again.

When a user lost the key, the password gets a new key, and all entries
are encrypted with it. That user may still know what they read before.
Change those passwords.

**--all** does every password you may give keys of, one by one.
**--unit** limits that to one unit and the units below it.

Needs **edit:keys**, and a key yourself.

## Objects

**add_node *password* *node***  
The password belongs to this node.

**remove_node *password* *node***  
The password no longer belongs to this node.

**add_host *password* *host***  
The password belongs to this host.

**remove_host *password* *host***  
The password no longer belongs to this host.

**add_device *password* *device***  
The password belongs to this device.

**remove_device *password* *device***  
The password no longer belongs to this device.

**add_client *password* *client***  
The password belongs to this client.

**remove_client *password* *client***  
The password no longer belongs to this client.

## Object Changelog

Every change to the object writes an entry: who made it, when, and what
was done. A change can carry a comment of its own, through the global
option **--changelog**.

An *entry_id* is the number the listing shows in front of an entry,
counted from 0.

Only the comment of an entry can be changed or removed. What was done
and by whom stays as it is.

**changelog *password***  
Show the changelog of the password object. Needs the ACL
**view:changelog**.

**edit_changelog *password* *entry_id* *comment***  
Set the comment of that entry, or replace the one it has. Needs the ACL
**edit:changelog**.

**del_changelog *password* *entry_id***  
Remove the comment of that entry. Needs the ACL **edit:changelog**.

**clear_changelog *password***  
Remove every entry of the changelog. Needs the ACL **clear:changelog**,
and the config parameter **allow_changelog_clearing** has to allow it
(see **otpme**(7)).

## Policy Management

**add_policy *password* *policy***  
Attach a policy to the password object. Needs the ACL **assign:policy**.

**remove_policy *password* *policy***  
Remove a policy from the password object. Needs the ACL
**remove:policy**.

## ACL Management

**add_acl *password* *owner_type* *owner* *acl***  
Add an access control entry.

**del_acl *password* *acl***  
Remove an access control entry.

**list_acls *password***  
Show all ACLs of the password object.

**enable_acl_inheritance *password***  
Take the default ACLs of the unit again.

**disable_acl_inheritance *password***  
Stop taking the default ACLs of the unit.

## Configuration

**config \[**-a**\] \[**-d**\] *password* *parameter* \[*value*\]**  
Set, append to or delete a config parameter.

**get_config *password* *parameter***  
Show a config parameter.

**show_config *password* \[*parameter*\]**  
Show the config parameters of the password object.

**description *password* \[*description*\]**  
Set the description. It is not encrypted.

**info \[**--language** *LANG*\] *password* \[*info*\]**  
Set free-form info text. It is not encrypted. If *info* is omitted, the
current info text is opened in the editor specified by the **EDITOR**
environment variable.

**dump_info \[**--language** *LANG*\] *password***  
Dump the info text to stdout.

## Import/Export

**export \[**--password** *PASS*\] *password***  
Export the password object. The entries stay encrypted.

**remove_orphans *password***  
Remove references to objects that are gone, and the keys of users that
are gone.

# OPTIONS

## Display Options

**--offline**  
Read the passwords this host keeps, without asking a node. Only with
**show**, **list**, **list_entries** and **show_password**.

**-a**  
Show all password objects.

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

**--keep-acls**  
Keep the ACLs when moving a password object.

**--password *PASS***  
Password for encrypting exports.

Global options are available for all commands. See **otpme**(1) for
details.

# EXAMPLES

**otpme-unit config passwords password_store_members 'role\|example.org/berlin/admins'**  
Give the members of the role "admins" the keys of the passwords in the
unit "passwords"

**otpme-unit sign_password_members passwords**  
Sign the members

**otpme-tool add_signer --signer-type password 'user\|example.org/berlin/alice'**  
On each host, as root: trust the signatures of alice

**otpme-pass add --node node1 --username root --url https://node1-idrac.example.org node1 idrac**  
Add the password "node1" with the entry "idrac", for the node "node1"

**otpme-pass add passwords/servers/server1 root**  
Add a password in the unit "passwords/servers"

**otpme-pass show_password node1 idrac**  
Show the entry "idrac" with its password

**otpme-node show_password node1**  
Show all passwords of the node "node1"

**otpme-pass change_entry --password node1 idrac**  
Change the password of the entry

**otpme-pass update_keys --all --unit passwords/servers**  
Bring the keys of all passwords below "passwords/servers" in line with
the members

**otpme-unit config passwords password_offline_cache host1,host2**  
Let the hosts "host1" and "host2" keep the passwords for offline use

**otpme-unit config -a passwords password_offline_cache 'group\|example.org/admins'**  
Let the hosts in the group "admins" keep them as well

**otpme-pass show_password --offline node1**  
Read the password this host keeps, without asking a node

# FILES

*/var/cache/otpme/offline/*user_uuid*/pass.json*  
The passwords a host keeps for the user, encrypted.

# SEE ALSO

**otpme**(1), **otpme**(7), **otpme-acls**(7), **otpme.conf**(5),
**otpme-unit**(1), **otpme-site**(1), **otpme-tool**(1),
**otpme-user**(1), **otpme-node**(1), **otpme-host**(1),
**otpme-device**(1), **otpme-client**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2026 the2nd. License: GPLv3
