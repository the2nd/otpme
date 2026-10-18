# NAME

otpme-role - manage OTPme roles

# SYNOPSIS

**otpme-role** *command* \[*options*\] \[*role*\]

# DESCRIPTION

**otpme-role** manages the roles of a realm.

A role is what things are assigned to. An access group, a client, a
share, a host, a node, a group, an OIDC scope and a VLAN all take a
role, and a role holds tokens. So the assignments are made once and
stay, and people come and go by being put into the role or taken out of
it.

A role can hold another role. **otpme-role add_role *parent* *child***
puts *child* into *parent*, and from then on the tokens of *child* reach
everything *parent* is assigned to. That is the direction to keep in
mind: what is assigned to the outer role flows to the tokens of the
inner one, and not the other way round.

A role lives in a unit, which is where its ACLs come from, and belongs
to one site.

# COMMANDS

## Role Management

**add \[**--groups** *group1,group2*\] \[**--roles** *role1,role2*\] *role***  
Create a role.  
**--groups** puts it into those groups and **--roles** into those roles,
which saves an **add_role** per role afterwards.

**del \[**--no-trash**\] *role***  
Delete a role. It goes to the trash, from where **otpme-trash**(1) can
bring it back; **--no-trash** deletes it right away.  
A role that still holds tokens or other roles is not deleted — take them
out first. A role that is a member of access groups is, and they are
named in the question before it happens. What held it keeps a reference
to something that is gone; **remove_orphans** on those objects clears it
up.  
A base role of the realm cannot be deleted at all.

**show \[**-a**\] \[**-z** *N*\] \[**--fields** *F1,F2*\] \[**--limit** *N*\] \[**--token-limit** *N*\] \[**--role-limit** *N*\] \[**--accessgroup-limit** *N*\] \[**--group-limit** *N*\] \[**--scope-limit** *N*\] \[**--policy-limit** *N*\] \[**--sort-by** *field*\] \[**--reverse**\] \[**--raw**\] \[**--csv**\] \[**--csv-sep** *sep*\] \[*role*\]**  
Show the roles, with their tokens, access groups, groups, scopes and
policies. Without a role you get all of them.

**-a**  
Also the roles you may only look at, not just the ones you may change.

**-z *N***  
How many roles to print.

**--fields *F1,F2***  
Print these columns and no others. The names are the ones in the header
of the table.

**--limit *N***  
How many of each kind to print per role: tokens, roles, access groups,
groups, scopes, policies.

**--token-limit *N*, **--role-limit** *N*, **--accessgroup-limit** *N*, **--group-limit** *N*, **--scope-limit** *N*, **--policy-limit** *N***  
The same for one of them, where the others should stay as they are.

**--sort-by *field*, **--reverse****  
Which column to sort by, and the other way round.

**--raw, **--csv**, **--csv-sep** *sep***  
For reading with something other than your eyes: **--raw** leaves the
header and the borders out, **--csv** prints one row per line with **;**
between the columns, and **--csv-sep** uses another separator.

**list \[**-a**\] \[**--attribute** *attribute*\] \[*regex*\]**  
List the role names, and with a regex only those that match it.  
You get the roles you may change; **-a** adds those you may only look
at.  
**--attribute** matches the regex against that attribute instead of the
name: **list --attribute enabled True** lists the roles that are
enabled. A value that is not text has to be spelled out — **\*** matches
none of it.

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
Move the role into another unit.  
Its ACLs move with it: the default ACLs of the old unit are taken away
and those of the new one are applied. **--keep-acls** leaves the ACLs of
the role as they are.

**touch *role***  
Re-index the object to fix potential index problems.

## Token Assignment

Putting a token into a role can sign the token. The signature says where
the token belongs: the user it is for, this role, the roles above it,
the access groups and the groups those roles are in, the interfaces of
**-i** and the *token_options*.

A host can be told whose signature it trusts. It then lets an SSH key in
only if the token carries a signature from one of them. So somebody the
host does not trust cannot get a key onto it by putting a token into a
role. The host side of this is **otpme-tool add_signer --signer-type
token,** see **otpme-tool**(1).

Signing usually happens on its own. It does when the token you are
logged in with says **auto_sign**, when you have auto-sign switched on
as a user, or when the role, its unit or its site say **auto_sign** (see
**otpme**(7)).

Some token types cannot be signed at all. Those are added without a
signature.

**add_token \[**-i** *interfaces*\] \[**--no-auto-sign**\] \[**--sign**\] \[**--tags** *tag1,tag2*\] \[**--share-notify**\|**--no-share-notify**\] \[**--no-persist-mount**\] \[**--skip-portal-token**\] *role* *token* \[*token_options*\]**  
Put a token into the role. From then on it reaches everything the role
is assigned to, and everything the roles above it are assigned to.

If the token is the SSO token of a site's portal — its name is that
site's **default_sso_token_name** — the tokens the portal manages for
that user go in as well, after a question, with the same options.
**--skip-portal-token** adds only the token you named.

**-i *interfaces***  
Only let this token log in over these: **tty**, **gui**, **ssh**, comma
separated. Without it the token counts for all of them.

*token_options*  
Options for the token in this role, at the end of the line. For an SSH
token these are the **authorized_keys** options its key is written with:
**command**, **from**, **restrict**, **no-pty**, **no-port-forwarding**,
**no-agent-forwarding**, **no-X11-forwarding**, **no-user-rc**,
**environment**, **permitopen**, **principals**, **tunnel** and
**cert-authority**. An option the type of token has no use for is
dropped.

**--sign**  
Sign, where nothing above asked for it. On a token that cannot be signed
this is an error.

**--tags *tag1,tag2***  
Put more tags into the signature.

**--no-auto-sign**  
Do not sign this time.

**--share-notify, **--no-share-notify****  
Whether the online hosts are told that there are new share permissions.

**--no-persist-mount**  
Do not persist new share mounts on hosts.

**remove_token \[**--keep-sign**\] \[**--share-notify**\|**--no-share-notify**\] \[**--no-persist-mount**\] \[**--skip-portal-token**\] *role* *token***  
Take the token out of the role. What it reached through the role, it no
longer reaches.

The signature goes with it. It says the token is in this role, and that
is no longer true. **--keep-sign** leaves it, for a token that is about
to go back in.

An SSO token takes the tokens of the portal with it, as above;
**--skip-portal-token** removes only the one you named.

**--share-notify, **--no-share-notify****  
Whether the online hosts are told that share permissions were revoked.

**--no-persist-mount**  
Keep persisted share mounts on hosts (transient unmount only).

**list_tokens \[**--return-type** *type*\] \[**--token-types** *t1,t2*\] *role***  
The tokens in this role. Only the ones put in here, not the ones that
reach it through a nested role.  
**--return-type** picks what is printed: **name** (default),
**read_oid**, **full_oid** or **uuid**. **--token-types** narrows it to
those types, for example **hotp,totp**.  
Disabled tokens are listed as well.

**list_users \[**--return-type** *type*\] *role***  
The users those tokens belong to. One user with three tokens in the role
is named once.

## Role Nesting

A role can hold other roles, and what the outer role is assigned to
reaches the tokens of the inner ones. See the **DESCRIPTION** above.

A *child_role* is looked for in the site of the role, or written as
*site***/***role* to take one from another site of the realm.
**remove_role** takes a UUID as well, which is how a reference to a role
that is gone is cleared out.

**add_role \[**--share-notify**\|**--no-share-notify**\] \[**--no-persist-mount**\] *role* *child_role***  
Put *child_role* into *role*. The tokens of *child_role* then reach
everything *role* is assigned to.

Nothing is copied: take the child out again and its tokens lose it all.

**--share-notify, **--no-share-notify****  
Whether the online hosts are told that there are new share permissions.

**--no-persist-mount**  
Do not persist new share mounts on hosts.

**remove_role \[**--share-notify**\|**--no-share-notify**\] \[**--no-persist-mount**\] *role* *child_role***  
Take *child_role* out of *role* again.

**--share-notify, **--no-share-notify****  
Whether the online hosts are told that share permissions were revoked.

**--no-persist-mount**  
Keep persisted share mounts on hosts (transient unmount only).

**list_roles \[**-r**\] *role***  
The roles this role holds. **-r** adds the roles those hold, all the way
down.

## Where this role is used

A command that starts with **list\_** answers what is in the role. One
that starts with **find\_** answers the other question: where the role
is used.

**--return-type** picks what they print: **name** (default),
**read_oid**, **full_oid** or **uuid**. A name from another site is
printed as *site***/***name*.

Disabled objects are listed as well, so a permission that is only
switched off is not mistaken for one that is gone.

**find_roles \[**-r**\] \[**--return-type** *type*\] *role***  
The roles this role is in, which is the other way round from
**list_roles**. **-r** adds the roles those are in, all the way up.

**find_accessgroups \[**--return-type** *type*\] *role***  
The access groups this role is in. Those are what say where a token of
the role may log in at all.

**find_clients \[**--return-type** *type*\] *role***  
The clients this role is assigned to.

**find_groups \[**--return-type** *type*\] *role***  
The groups this role is in.

**find_shares \[**-r**\] \[**--return-type** *type*\] *role***  
The shares this role opens. **-r** adds the shares the roles below it
open.  
Here **--return-type** starts at **path**, which is the share name with
its site in front.

**find_scopes \[**--return-type** *type*\] *role***  
The OIDC scopes this role is assigned to. They decide what a relying
party learns about the user.

**find_acls *role***  
The ACLs this role holds on other objects, i.e. what the members of this
role may do elsewhere. Not the ACLs that lie on the role itself — those
are **list_acls**.

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

A VLAN that is switched off answers nothing, on either way in: neither
where the VLAN names the role nor where the **vlans** parameter names
the VLAN. Switching a VLAN off therefore takes away every assignment it
is part of.

Both ways write a warning to the log when an assignment is skipped for
that reason. Without one, an assignment to a VLAN that is off looks
exactly like no assignment at all.

A **vlans** parameter can also name a VLAN that no longer exists. Its
UUID stays in the parameter, and it is ignored with a warning in the
log.

Two VLANs naming the same object at the same distance are a mistake in
the configuration, and OTPme cannot resolve it: it takes the first of
them by name, every time, and writes a warning to the log.

## Hosts and Devices

A role holds hosts and devices as well as tokens. A machine gets two
things from the role: the VLAN of the role at port authentication, and
access to the shares the role is assigned to.

The share part only matters where the share says so. A share with
**limit_by_hosts** set asks which hosts may reach it, and a host in this
role — or in a role nested in it — may. A role that is switched off does
not count. Without **limit_by_hosts** a share does not ask about hosts
at all.

This is not the way round in which a host takes things from a role. A
host names its own roles, with **otpme-host add_role,** and that is what
decides which tokens may log in there and whose accounts are synced to
it — see **otpme-host**(1). Here the role names the host, which is what
the VLAN and the shares are read from. Both are needed, for different
things.

A device is a machine that cannot authenticate itself, a printer or an
IP phone, and is let onto the network by its MAC address. See
**otpme-device**(1).

**add_host *role* *host***  
Put a host into the role. Host names are unique in the realm, so the
host is given by its name alone, whatever site it is in.

**remove_host *role* *host***  
Take it out again.

**list_hosts *role***  
The hosts in this role.

**add_device *role* *device***  
Put a device into the role.

**remove_device *role* *device***  
Take it out again.

**list_devices *role***  
The devices in this role.

## Dynamic Groups

A dynamic group is a group on the host itself, not an OTPme group —
**dialout**, **video**, **wheel**. It has to exist there already. At
login **pam_otpme** puts the user into it for that session.

A token in this role gets the dynamic groups of the role, and those of
the roles this role is in. What else gives a user one, and why a name
that is already an OTPme group is refused, is under **Dynamic Groups**
in **otpme**(7).

**add_dynamic_group *role* *group***  
Give the members of this role that group on the host they log in to.

**remove_dynamic_group *role* *group***  
Take it away again.

**list_dynamic_groups *role***  
The dynamic groups of this role.

## Sync Users

A sync user is a user whose account is copied to a host without any
token of theirs going with it. The account exists on the host — a file
belongs to them, a service runs as them — and nobody logs in with it.

A host that names this role takes its sync users — **otpme-host
add_role**, not **otpme-role add_host,** which is for the VLAN and the
shares. A sync group that names this role takes them as well, and so do
the roles inside this one.

A user who is to log in there needs a token in the role instead. That
brings the account along with it.

**add_sync_user *role* *user***  
Have that user's account copied to the hosts that name this role.  
Needs the ACL **add:sync_user**.

**remove_sync_user *role* *user***  
Stop that.  
Needs the ACL **remove:sync_user**.

**list_sync_users \[**--return-type** *type*\] *role***  
The sync users of this role.  
Needs the ACL **view:sync_users**.

## Policy Management

A *policy* is the name of a policy, not a path. It is looked for in the
site of the role. Which policies there are, and what each of them does,
is in **otpme-policy**(1).

Three types can go on a role: **logintimes**, **forcetoken** and
**autodisable**. A policy of any other type is refused here.

A policy on a role applies to the logins that role lets through, and to
no others. At a login to a host, a node or a client, the policies of a
role run when both halves hold: the role is assigned to that host, node
or client, and the role holds the token. Either half may run through
nested roles, and every role of the chain counts — the one assigned to
the host, the one holding the token, and the ones between them.

So login times on a role say when the members of that role may log in to
the machines that role gets them onto, and say nothing about any other
machine. A role that is switched off says nothing at all.

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
**find_acls** under **Where this role is used** above.

**add_acl *role* *owner_type* *owner* *acl*\[**:***value*\]\[**,***acl*\[**:***value*\]\]**  
Give a role or a token one or more ACLs on this role.  
*owner_type* is **role** or **token**, and *owner* the path of that role
or token. An ACL may carry a value, for example **view:tokens**, and
several are separated by commas.  
Needs the ACL **add:acl**.

**del_acl *role* *acl*\[**,***acl*\]**  
Take those ACLs away again.  
Here an *acl* is the whole entry, owner and all, the way **list_acls**
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

A move by somebody who does not hold **add:acl** and **delete:acl** on
the role leaves its ACLs alone as well, and says so. Otherwise moving an
object into a unit would be a way of handing yourself the default ACLs
of that unit.

Needs the ACL **enable:acl_inheritance**.

**disable_acl_inheritance *role***  
Stop inheriting them. Only the ACLs on the role itself count from then
on.  
Needs the ACL **disable:acl_inheritance**.

## Extensions and LDAP Attributes

A role is also an LDAP entry, and an extension is what gives it one: the
object classes it is of, and the attributes those classes allow. What
**ldapd** serves and what **show_ldif** prints comes from them.

A new role gets two, and keeps them unless you take them away:

> -   **base** makes it an **organizationalRole** with **cn** and
>     **description**.
>
> -   **posix** gives a role no class and no attribute of its own. It is
>     there for the other direction: when a token goes into the role or
>     out of it, the POSIX attributes of the groups the role is in have
>     to follow, **memberUid** among them, and that runs through this
>     extension.

So a role without the **posix** extension stops keeping those groups up
to date.

**add_extension *role* *extension***  
Add **base** or **posix** to the role. An extension that is not for
roles is refused, and so is one the role already has.

**remove_extension *role* *extension***  
Take it away again, with the classes and attributes it brought.

**add_attribute *role* *attribute***=**\[*value*\]**  
Set an LDAP attribute of the role.

Only an attribute one of its extensions allows: there is no setting an
attribute OTPme knows nothing about. An attribute can hold more than one
value, so this adds one and leaves the others.

The ACL is per attribute, **add:attribute:***attribute*, and a plain
**add:attribute** covers all of them.

**del_attribute *role* *attribute***=**\[*value*\]**  
Remove that value, or the whole attribute where no value is given.  
A mandatory attribute of a class the role is of cannot be removed, and
neither can a read-only one. The ACL is
**delete:attribute:***attribute*.

**add_object_class *role* *class***  
Add an LDAP object class to the role, beyond the ones its extensions
brought.

**del_object_class *role* *class***  
Remove one again.

**show_ldif *role* \[**-a** *attribute1,attribute2*\]**  
The role as LDAP sees it. **-a** prints only those attributes.

## Configuration

Seven config parameters can be set on a role. What each of them does is
under **CONFIG PARAMETERS** in **otpme**(7); here is what they are
about:

> -   **device_token_suffix**, **device_token_types**,
>     **max_device_tokens** and **device_token_mschap** make the role
>     one the SSO portal offers for device tokens, and say what it
>     creates there. The first of them is the switch: a role without it
>     is not shown in the portal at all.
>
> -   **auto_sign** signs a token for the assignment when it is put into
>     this role, the way **add_token --sign** does by hand.
>
> -   **changelog** and **allow_changelog_clearing** are about the
>     history of the object, see **Object Changelog** below.

A value is looked for on the role, then on the unit above it, then on
the unit above that, and last on the site. The nearest one wins, and the
realm holds none. A site can take that away for single parameters with
**force_site_config_parameters**: those are read from the site and
nowhere else, whatever the role says.

**config \[**-d**\] \[**-a**\] *role* *parameter* \[*value*\]**  
Set a parameter on the role itself.

**-a** appends to a parameter that holds a list instead of replacing it.

**-d** removes the parameter from the role, or with a value only that
one value from a list. What the role gets afterwards is whatever the
units above it or the site say — **-d** is not the same as setting the
parameter to its default.

The ACL is per parameter, **set:config:***parameter*.

**show_config *role* \[*parameter*\]**  
The parameters set on the role itself, or only the one named. Nothing is
shown for a parameter that the role gets from a unit or from the site.

**get_config *role* *parameter***  
What the parameter comes to for this role, once the role, its units and
its site have been looked at. So this answers what applies, where
**show_config** answers what was set here.

**description *role* \[*description*\]**  
Set the description. Without one OTPme asks and offers the current text
for editing.  
It is an LDAP attribute of the role as well (**description**, from the
**base** extension), so it is what an LDAP client sees.

**info \[**--language** *LANG*\] *role* \[*info*\]**  
Set free-form info text. If *info* is omitted, the current info text is
opened in the editor specified by the **EDITOR** environment variable.  
Without **--language** the text is the administrator's own note about
the object, which no user is ever shown. A text written with a language
is one for the users of that language: a role named in
**device_token_roles** shows it on the SSO portal, in the language of
whoever is looking, see **otpme**(7).

**dump_info \[**--language** *LANG*\] *role***  
Write one of those texts to stdout, for reading it with something other
than the editor.  
**--language** picks which one, the same way as for **info**; without it
you get the note of the administrator. A language the role has no text
for gives nothing and is not an error.

## Object Changelog

Every change to the object writes an entry: who made it, when, and what
was done. A change can carry a comment of its own, through the global
option **--changelog**.

Unless the **changelog** config parameter says otherwise. It is read
along the cascade of the role, and nothing is written where it is off —
not for that role, and not for the ones below a unit that switched it
off. Without any value anywhere it is on.

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

## Export and Cleanup

Both write to stdout. There is no import on this page: reading an export
back in is **otpme-tool import,** see **otpme-tool**(1).

**remove_orphans** asks before it changes anything; the global option
**-f** skips the question.

**export \[**--password** *password*\] *role***  
Write the whole object of the role to stdout, as JSON.

Without **--password** it is written as it is, in clear. With one, a key
is derived from that password and the object is encrypted with it; the
salt goes into the output, so the password is all you need to read it
back.

What a role holds are references by UUID — its tokens, its roles, its
hosts, its devices — so an export says something only in the realm it
came from. It carries no secret of any token.

Needs the ACL **export**.

**remove_orphans *role***  
Remove what the role still points at although it is gone.

On a role that is its ACLs, its policies, its signatures, and the
tokens, roles, hosts and devices in its member lists. A token that was
deleted leaves its UUID in the list, and so does a role, a host or a
device.

It shows everything it found and asks once for all of it. It asks
nothing and changes nothing when it finds nothing.

Needs the ACL **remove:orphans**.

# OPTIONS

Every option belongs to one command and is described with that command
above. A short option means what that command makes of it.

Global options work with every command, see **otpme**(1).

# CONFIG PARAMETERS

Which parameters a role takes is under **Configuration** above, and what
each of them does is in **otpme**(7).

# EXAMPLES

The examples use the site **berlin** of the realm **example.org**.

## Letting people onto the WLAN

**otpme-role add wlan-users**  
A role. By itself it does nothing — it is the next step that gives it a
meaning.

**otpme-accessgroup add_role wlan wlan-users**  
Assign it to the access group the WLAN authenticates against. Now the
tokens in the role may log in there, and nowhere else by way of this
role. See **otpme-accessgroup**(1).

**otpme-role add_token wlan-users alice/laptop**  
Put a token in. alice gets onto the WLAN with it from now on.

**otpme-role remove_token wlan-users alice/laptop**  
Take it out again. What it reached through the role is gone with it, and
the signature of the assignment too.

## Letting a whole group of people on

**otpme-role add_role wlan-users office-staff**  
Put **office-staff** into **wlan-users**. Everybody in **office-staff**
is now on the WLAN, without a token of theirs being named here. The
direction is from the outer role to the tokens of the inner one.

**otpme-role list_roles -r wlan-users**  
Which roles are inside it, all the way down.

**otpme-role find_roles -r office-staff**  
And the other way: which roles **office-staff** is in.

## Device tokens from the SSO portal

A device token is a password of its own for one device: a notebook on
the WLAN, a phone fetching mail. The user makes it in the SSO portal, so
nobody has to hand out a password for it.

**otpme-role config wlan-users device_token_suffix wlan**  
This is the switch: without a suffix the role is not offered in the
portal at all. A token of the device **iphone** is then called
**iphone-wlan**.

**otpme-role config wlan-users device_token_mschap True**  
WLAN with PEAP/MSCHAPv2 needs it. It keeps the NT hash of the password
on the server, which is why it is off unless the role says so.

**otpme-role config wlan-users max_device_tokens 5**  
Five devices per user.

**otpme-site config berlin device_token_roles wlan-users**  
Offer the role to the users of this site. It can also be said per user
or per unit, see **otpme**(7).

**otpme-role info --language en wlan-users**  
What the portal tells the user about the role, in English. A text
written without a language is your own note and is shown to nobody.

## What does a role actually grant?

**otpme-role show wlan-users**  
Its tokens, roles, access groups, groups, scopes and policies in one
table.

**otpme-role find_accessgroups wlan-users**  
Where its tokens may log in.

**otpme-role find_shares -r sw-admins**  
Which shares they can mount, the roles below it included.

## An SSH key the hosts accept

**otpme-role config sw-admins auto_sign True**  
Sign every token this role takes in from now on. Without it you sign one
at a time with **add_token --sign**.

**otpme-role add_token sw-admins alice/ssh**  
The key goes in and is signed with your own. A host told to trust you
for token signatures lets it in; see **Token Assignment** above.

## Machines in a role

**otpme-vlan add_role office-vlan office-hosts**  
Put the role into a VLAN. Its tokens, hosts and devices get it at port
authentication. See **otpme-vlan**(1).

**otpme-role add_host office-hosts client1**  
A host in the role reaches the shares the role is assigned to, and gets
its VLAN. What tokens may log in to that host is the other way round,
**otpme-host add_role.**

**otpme-role add_device office-hosts printer1**  
The same for a device that is let onto the network by its MAC address.

## Looking after one

**otpme-role add_policy wlan-users office-hours**  
Attach a policy. Three types fit a role; see **Policy Management** above
for when they take effect.

**otpme-role remove_orphans wlan-users**  
Clean out what the role still points at although it is gone.

# FILES

*/var/lib/otpme/*  
The objects of the realm, on a node. A role lives in the unit it was
created in. A host holds no full role, only the view it answers a login
with: the UUIDs of the members, the login interfaces they may use, the
dynamic groups and the policies on the role.

*/var/cache/otpme/ssh/authorized_keys/*user/authorized_keys**  
The SSH keys that may log in to this host, one file per user. A key is
only written here while a role of the host holds the token — see
**otpme-host**(1) and **add_role** there.

# SEE ALSO

**otpme**(1), **otpme**(7), **otpme-acls**(7), **otpme-user**(1),
**otpme-token**(1), **otpme-group**(1), **otpme-accessgroup**(1),
**otpme-host**(1), **otpme-device**(1), **otpme-vlan**(1),
**otpme-share**(1), **otpme-unit**(1), **otpme-policy**(1),
**otpme-tool**(1), **otpme-trash**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2026 the2nd. License: GPLv3
