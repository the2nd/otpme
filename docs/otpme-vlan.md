# NAME

otpme-vlan - manage OTPme VLANs

# SYNOPSIS

**otpme-vlan** *command* \[*options*\] \[*vlan*\]

# DESCRIPTION

**otpme-vlan** adds, changes and deletes VLANs. A VLAN says which
network a port is put into. When a switch or an access point asks a node
for a port, the answer carries the VLAN as **Tunnel-Private-Group-Id**:
the VLAN ID if one is set, otherwise the name of the VLAN, which is what
switches with named VLANs (e.g. Cisco) expect.

> -   802.1X: the switch is a client with **enable_dot1x**, see
>     **otpme-client**(1), and the user logs in with a password token or
>     a PIV token. The answer carries the VLAN of that token.
>
> -   MAB: the switch asks with the MAC address of a host or a device.
>     The answer carries the VLAN of that host or device.

There are two ways to give an object a VLAN: make it a member of the
VLAN, or name the VLAN in the **vlans** config parameter of the object.
A member wins over the config parameter.

A VLAN that is disabled is passed over, as if it named nobody, and a
warning is logged.

## Membership

**add_token**, **add_role**, **add_host** and **add_device** make an
object a member. A VLAN counts on its own site only: the node that
answers looks at the VLANs of its site. The members are kept on the
VLAN, not on the objects. So a site can put objects of another site,
e.g. the tokens of users added there, into its own VLANs without
changing them. It needs no **vlan_trusts** for that, because the VLAN
and the network are its own. If a switch of another site asks, the
membership does nothing there: that site looks at its own VLANs, then at
the **vlans** config parameter. If neither gives a VLAN, the answer has
none, and the switch uses the VLAN set on the port.

The closest one wins. First a VLAN that names the object itself, then
one that names a role the object is in, then one that names a role that
role is in, and so on up. So a single token can get another VLAN than
its role, and a role nested in another role can have a VLAN of its own.
If two VLANs are equally close, e.g. the object is in two roles of the
same level, each in another VLAN, the VLAN whose name sorts first is
used, and a warning names both.

An object can be a member of one VLAN per site. Adding it to a second
one is refused, with the VLAN it is in. Only direct members count here:
a role in another VLAN is no conflict, the member is meant to override
it.

## The vlans config parameter

It can be set on sites, units, users, tokens, hosts and devices. It
counts only when no VLAN of the site names the object or one of its
roles. To name a VLAN in it, you need **assign** on the VLAN. So you can
let someone give out the VLAN guests without letting them put anybody
into the VLAN servers.

An object can name one VLAN per site, as *site/vlan* for a VLAN of
another site. This is for objects used at more than one site, e.g. users
added on one site while every site runs its own VLANs. The node that
answers uses the VLAN of its own site. If there is none, it uses the
first VLAN its **vlan_trusts** allow, in the order of the entries.

## Across sites

A VLAN of another site, or a VLAN for an object of another site, is used
only if the site that answers allows it in its **vlan_trusts**, as
*site*\[**:***vlan_site*\[**/***vlan*\]\], see **otpme**(7). The port is
in the network of that site, so that site decides. **assign** alone is
not enough: the site that names the VLAN checks it on its own copy of
the VLAN.

# COMMANDS

## VLAN Management

**add *vlan* \[*vlan_id*\]**  
Create a VLAN. With a path, e.g. **vlans/office/guest**, it goes into
that unit; else into the unit a **defaultunits** policy names, see
**otpme-policy**(1), or into **vlans**. The name goes to the switch as
it is, so its case is kept. It is unique in the site, whatever unit it
is in, and may be **max_vlan_name_len** long (64 by default).  
*vlan_id* sets the VLAN ID at once, see **VLAN ID**; a VLAN ID that is
not 1 to 4094, or that another VLAN of the site has, is refused before
the VLAN is made.  
Needs **add:vlan** on the unit.

**del \[**--no-trash**\] *vlan***  
Delete the VLAN. It goes to the trash, see **otpme-trash**(1);
**--no-trash** deletes it right away.  
The question says how many members it still has. They lose their VLAN
with it: the member list is on the VLAN, so nothing is left behind.
Objects that name the VLAN in their **vlans** config parameter keep a
reference to something that is gone. They are not listed, because that
parameter is not in the index.  
Needs **delete:object** on the VLAN or **delete:vlan** on the unit.

**show \[**-a**\] \[**-z** *N*\] \[**--fields** *F1,F2*\] \[**--limit** *N*\] \[**--policy-limit** *N*\] \[**--sort-by** *field*\] \[**--reverse**\] \[**--raw**\] \[**--csv**\] \[**--csv-sep** *sep*\] \[*vlan*\]**  
Without a VLAN: a table of all of them, with their unit, status, VLAN
ID, tokens, roles, hosts, devices, policies, ACL inheritance and
description. A member of another site has its site after it, a disabled
one **(D)**.

**-a**  
Also the VLANs you may only look at, not just the ones you may change.

**-z *N***  
How many VLANs to print.

**--fields *F1,F2***  
Print these columns and no others. The names are the ones in the header
of the table.

**--limit *N***  
How many of each kind to print per VLAN: tokens, roles, hosts, devices,
policies.

**--policy-limit *N***  
The same for the policies only.

**--sort-by *field*, **--reverse****  
Which column to sort by, and the other way round.

**--raw, **--csv**, **--csv-sep** *sep***  
**--raw** leaves the header and the borders out, **--csv** prints one
row per line with **;** between the columns, and **--csv-sep** uses
another separator.

A column you may not see says **-**. With a VLAN named, this prints the
VLAN itself, one value per line: **VLAN_ID**, **TOKENS**, **ROLES**,
**HOSTS** and **DEVICES**; one you may not see is empty. That needs
**view_public:object**.

**show_oid \[**--full**\] *vlan***  
Show the OID of the VLAN: **vlan\|\<realm\>/\<site\>/\<name\>**. With
**--full** the full OID, which names the unit as well:
**vlan\|\<realm\>/\<site\>/\<unit_path\>/\<name\>**.  
Needs the ACL **view_public:object**.

**show_uuid *vlan***  
Show the UUID of the VLAN.  
Needs the ACL **view_public:object**.

**list \[**-a**\] \[**--attribute** *attribute*\] \[*pattern*\]**  
List the VLAN names, and with a pattern only those that match it, see
**SELECTING OBJECTS** in **otpme**(1). You get the VLANs you may change;
**-a** adds those you may only look at. **--attribute** matches the
pattern against that attribute instead of the name.

**enable *vlan***  
**disable *vlan***  
A disabled VLAN is not handed out. The next assignment counts instead: a
VLAN that names a role the object is in, or the **vlans** config
parameter. The log says "Ignoring disabled VLAN", as it looks the same
as no assignment from outside. Tables show the status.  
Needs **enable:object** or **disable:object**.

**rename *vlan* *new_name***  
Rename the VLAN. The new name must not be in use in the site. Members
and the **vlans** config parameters keep it: they name it by its UUID.
Without a VLAN ID the switch gets the new name from then on.  
Needs **rename:object**.

**move \[**--keep-acls**\] *vlan* *unit***  
Move the VLAN into another unit. It keeps its ACLs; where ACL
inheritance is on for it (off for VLANs by default, see
**enable_acl_inheritance**), the default ACLs of the old unit are taken
away and those of the new one given. **--keep-acls** keeps all ACLs as
they are.  
Needs **move** on the VLAN and **add:vlan** on the unit.

**touch *vlan***  
Write the index entries of the VLAN again.  
Needs **touch**.

**auto_disable *vlan* *time***  
Set auto-disable time. It is either a relative time with a leading
**+**, e.g. **+30D**, or an absolute one, e.g. **"09:53 13.06.2023"**.
The units are **s**, **m**, **h**, **D**, **W**, **M** and **Y**, see
**otpme**(7). A relative time counts from when it is set, and again from
when the VLAN is enabled. **0** removes it.  
Needs **edit:auto_disable**.

## Members

A member is named by the VLAN, see **DESCRIPTION**. An object can be a
member of one VLAN per site; adding it to a second one is refused, and
the message names the one it is in. That is checked after the ACL, so
only somebody who may add it here is told.

**add_token *vlan* *user/token***  
Put a token into the VLAN, for 802.1X: the token logs in, and its VLAN
is sent to the switch. User names are unique in the realm, so the token
may belong to a user of any site. The token is not signed, whatever
auto-sign says: nothing checks a signature for a VLAN.  
Needs **add:token**.

**remove_token *vlan* *user/token***  
Take the token out of the VLAN. A UUID is taken as well, which is how a
token that is gone is cleared out.  
Needs **remove:token**.

**add_role *vlan* *role***  
Put a role into the VLAN. Every token, host and device of the role is
then in the VLAN, and so is every role nested in it, unless a VLAN names
one of them more closely.  
The role is looked for in the site of the VLAN, or written as
*site/role* to take one from another site of the realm.  
Needs **add:role**.

**remove_role *vlan* *role***  
Take the role out of the VLAN. It is named as for **add_role**, or by
its UUID, which is how a role that is gone is cleared out.  
Needs **remove:role**.

**add_host *vlan* *host***  
Put a host into the VLAN, for MAB: the switch asks with the MAC address
of the host. Host names are unique in the realm, so the host is given by
its name alone, whatever site it is in.  
Needs **add:host**.

**remove_host *vlan* *host***  
Take the host out of the VLAN. A UUID is taken as well, for a host that
is gone.  
Needs **remove:host**.

**add_device *vlan* *device***  
Put a device into the VLAN, for MAB, as for a host. Device names are
unique in the realm.  
Needs **add:device**.

**remove_device *vlan* *device***  
Take the device out of the VLAN. A UUID is taken as well, for a device
that is gone.  
Needs **remove:device**.

## VLAN ID

What the switch gets is **Tunnel-Private-Group-Id**, with
**Tunnel-Type** VLAN and **Tunnel-Medium-Type** IEEE-802. It is the VLAN
ID where one is set, else the name of the VLAN, which is what a switch
with named VLANs expects.

**vlan_id *vlan* \[*vlan_id*\]**  
Set the 802.1Q VLAN ID, a number from 1 to 4094; anything else is
refused. It is read as a number, so **010** is **10**. A VLAN ID that
another VLAN of the site has is refused as well, and the message names
that VLAN: two VLANs with one ID would be two names for one network.
Without *vlan_id* the VLAN ID is removed, and the switch gets the name
from then on.  
The nodes of other sites get the VLAN ID as well: a site may hand out a
VLAN of another one, see **vlan_trusts** in **otpme**(7).  
Tables show it to whoever has **view:vlan_id** or **edit:vlan_id**.  
Needs **edit:vlan_id**.

## Object Changelog

Every change to the object writes an entry: who made it, when, and what
was done. A change can carry a comment of its own, through the global
option **--changelog**.

Unless the **changelog** config parameter says otherwise. It is read
along the cascade (VLAN, unit, site), and nothing is written where it is
off. Without any value anywhere it is on.

An *entry_id* is the number the listing shows in front of an entry,
counted from 0.

Only the comment of an entry can be changed or removed. What was done
and by whom stays as it is.

A command that changes something asks first; the global option **-f**
skips the question.

**changelog *vlan***  
Show the changelog of the VLAN, one entry per line: its *entry_id*, the
time, who made the change and what was done, then a detail in round
brackets and the comment in square brackets where there are any. Needs
the ACL **view:changelog**.

**edit_changelog *vlan* *entry_id* *comment***  
Set the comment of that entry, or replace the one it has. That writes an
entry of its own. Needs the ACL **edit:changelog**.

**del_changelog *vlan* *entry_id***  
Remove the comment of that entry. The entry itself stays, and an entry
without a comment is refused. That writes an entry of its own. Needs the
ACL **edit:changelog**.

**clear_changelog *vlan***  
Remove every entry of the changelog. Afterwards it holds one entry: that
it was cleared.  
This needs more than the ACL **clear:changelog**: the config parameter
**allow_changelog_clearing** has to allow it (see **otpme**(7)). It is
true by default, but where no value is found at all, clearing is
refused. A value set on the token you are signed in with counts first.
Without one, the value of the object counts, read along its cascade.

## Policy Management

A *policy* is the name of a policy, not a path. It is looked for in the
site of the VLAN. Which policies there are, and what each of them does,
is in **otpme-policy**(1).

Two policy types fit a VLAN:

-   **authonaction** asks for a login again before the actions of the
    VLAN, see **AUTH ON ACTION HOOKS**.

-   **autodisable** disables the VLAN after a while; it is then no
    longer handed out, see **disable**. One set with **auto_disable -u**
    (unused for) is refused: a VLAN does not keep its last use.

Attaching and detaching ask before they change anything; the global
option **-f** skips the question.

**add_policy *vlan* *policy***  
Attach a policy to the VLAN.  
A policy has a list of object types it is for; one that does not name
**vlan** is refused. So is a second policy of a type that allows only
one per object, even when the first one is disabled, and a policy the
VLAN already has.  
Needs the ACL **assign:policy**.

**remove_policy *vlan* *policy***  
Remove a policy from the VLAN.  
Needs the ACL **remove:policy**, and that one verbatim: a plain
**remove** does not cover it. Detaching a policy takes away what it
enforces, so it must not be cheaper than attaching one.

**list_policies \[**--return-type** *TYPE*\] \[**--policy-types** *t1,t2*\] *vlan***  
List the policies attached to the VLAN, the disabled ones too, marked
**(disabled)**. Use **--return-type** to select the attribute returned
(**name**, **read_oid**, **full_oid**, **uuid**); without it the names.
Only the names are marked. Use **--policy-types** to list only policies
of the given types; these are policy types, not policy names.  
Needs the ACL **view:policies**.

## ACL Management

An ACL says what somebody may do with this VLAN. The somebody is a role
or a token, never a user.

What the three forms **acl**, **+acl** and **++acl** mean is under
**ACLs** in **otpme**(7). Tab completion after **add_acl** offers the
ACLs a VLAN knows. A VLAN has no default ACLs, **+acl** and **++acl**
are refused: nothing lies in a VLAN that could get them.

Besides the ACLs every object has, these matter for a VLAN:

> **assign**  
> Name this VLAN in the **vlans** config parameter of an object, see
> **DESCRIPTION**.
>
> **edit:vlan_id, **view:vlan_id****  
> Change and see the VLAN ID, see **VLAN ID**.
>
> **add:token, **add:role**, **add:host**, **add:device****  
> Add members, see **Members**. **remove:** with the same values takes
> them out again, **view:** with the plural (**view:tokens**, ...) lists
> them.

Adding and removing ask first, once for the whole command; the global
option **-f** skips the question.

**add_acl *vlan* *owner_type* *owner* *acl*\[:*value*\]\[,*acl*\[:*value*\]\]**  
Give a role or a token one or more ACLs on this VLAN.  
*owner_type* is **role** or **token**. *owner* names it the way
**list_acls** prints it: a role as *site/name*, e.g.
**munich/helpdesk**, or by its name alone on its own site; a token as
*user/token*, e.g. **alice/login**. An ACL can carry a value, for
example **view:vlan_id**. To give several ACLs at once, separate them
with commas: **assign,view:vlan_id**.  
Needs the ACL **add:acl**.

**del_acl *vlan* *acl*\[,*acl*\]**  
Take those ACLs away again.  
Here an *acl* is the whole entry, owner and all, the way **list_acls**
prints it: **role:munich/helpdesk:assign**.  
Needs the ACL **delete:acl**.

**list_acls *vlan***  
Show the ACLs that lie on this VLAN, i.e. who may do what with it.  
Needs the ACL **view:acl**.

**enable_acl_inheritance *vlan***  
Let a move of the VLAN swap its default ACLs: what the old unit handed
down is taken away, and what the new unit hands down is given. It does
not by default; a move then leaves the ACLs of the VLAN as they are.

Only a move asks this. A new VLAN gets the default ACLs of its unit, and
**add_acl -a** or **-r** on a unit reach it either way. A move with
**--keep-acls** leaves its ACLs alone all the same.

A move by somebody who does not hold **add:acl** and **delete:acl** on
the VLAN leaves its ACLs alone as well, and says so. Otherwise moving an
object into a unit would be a way of handing yourself the default ACLs
of that unit.

Needs the ACL **enable:acl_inheritance**.

**disable_acl_inheritance *vlan***  
A move leaves the ACLs of the VLAN as they are again.  
Needs the ACL **disable:acl_inheritance**.

## Configuration

A VLAN has two config parameters, see **CONFIG PARAMETERS**.

**config \[**-d**\] \[**-a**\] *vlan* *parameter* \[*value*\]**  
Set a parameter on the VLAN.

**-d**  
Remove the parameter from the VLAN, or with a value only that one value
from a list. It is not set back to a default: what applies afterwards is
what the units or the site say.

**-a**  
Append the value to a parameter that holds a list, instead of replacing
what is there.

Needs the ACL **set:config:\<parameter\>**.

**show_config *vlan* \[*parameter*\]**  
The parameters set on the VLAN itself, or only the one named. Nothing is
shown for a parameter that the VLAN gets from a unit or from the site.  
Needs the ACL **view:config:\<parameter\>**.

**get_config *vlan* *parameter***  
What the parameter comes to for the VLAN, once the VLAN, its units and
the site have been looked at. So this answers what applies, where
**show_config** answers what was set here.  
Needs the ACL **view:config:\<parameter\>**.

**description *vlan* \[*description*\]**  
Set the description. Without one OTPme asks and offers the current text
for editing.  
Needs the ACL **edit:description**.

**info \[**--language** *LANG*\] *vlan* \[*info*\]**  
Set free-form info text. If *info* is omitted, the current info text is
opened in the editor named by the **EDITOR** environment variable.  
Without **--language** the text is the administrator's own note. Nothing
shows the info of a VLAN to a user, so a text for a language stays a
note as well.  
Needs the ACL **edit:info**.

**dump_info \[**--language** *LANG*\] *vlan***  
Write one of those texts to stdout. **--language** picks which one;
without it you get the note of the administrator.  
Needs the ACL **view:info**.

## Export and Cleanup

**export \[**--password** *password*\] *vlan***  
Write the whole object of the VLAN to stdout, as JSON: its VLAN ID,
members, ACLs, policies, config parameters and the rest. **otpme-tool
import** reads it back.  
A VLAN holds no key and no secret, so **--password** has nothing to
encrypt: the output is in clear either way.  
Needs the ACL **export**.

**remove_orphans *vlan***  
Remove references to objects that are gone: members of the VLAN that
were deleted (tokens, roles, hosts and devices), orphan ACLs and
policies.  
It asks once for what it found; the global option **-f** skips the
question.  
Needs the ACL **remove:orphans**.

# OPTIONS

Every option belongs to one command and is described with that command
above.

Global options work with every command, see **otpme**(1).

# CONFIG PARAMETERS

Set them with **config**, see **Configuration**. A value is looked up on
the VLAN, then on its unit and the units above it, then on the site; the
first one found counts. A parameter the site names in
**force_site_config_parameters** is taken from the site, whatever the
VLAN or its units say. The full descriptions are in **otpme**(7).

**changelog (bool, default: true)**  
Whether the commands that change the VLAN write an entry into its
changelog, see **Object Changelog**.

**allow_changelog_clearing (bool, default: true)**  
Whether **clear_changelog** is allowed on the VLAN. A value on the token
you are signed in with counts first, see **Object Changelog**.

Set on the site or a unit, not on the VLAN:

**max_vlan_name_len (int, default: 64)**  
The longest name a VLAN may get, checked by **add** and **rename**.

The **vlans** parameter that assigns a VLAN is not one of the VLAN: it
is set on the object that gets it, see **DESCRIPTION**.

# EXAMPLES

## Setting up VLANs

**otpme-vlan add guests 100**  
Add the VLAN **guests** with the VLAN ID 100; the ID is what the switch
gets.

**otpme-vlan add printers**  
Add a VLAN without an ID; the switch gets the name **printers** instead.

**otpme-vlan vlan_id guests 110**  
Change the VLAN ID; you are asked first.

## Members

**otpme-vlan add_role guests employees**  
Every token, host and device in the role **employees**, or in a role
nested in it, gets the VLAN.

**otpme-vlan add_role servers admins**  
**admins** is nested in **employees**: its members get **servers**, and
everyone else in **employees** keeps **guests**.

**otpme-vlan add_token servers alice/login**  
A single token gets **servers**, whatever VLAN its roles are in.

**otpme-vlan add_host printers printer1**  
A host, for MAB: the switch asks with the MAC address of **printer1**.

## The vlans config parameter

**otpme-vlan add_acl guests role helpdesk assign**  
Let the role **helpdesk** name **guests** in the **vlans** config
parameter of an object.

**otpme-token config alice/login vlans guests**  
Name the VLAN on the token instead; this needs **assign** on the VLAN.
It only counts where no VLAN of the site names the token or one of its
roles.

## Across sites

**otpme-host config client1 vlans berlin/guests**  
Give **client1**, a host of site **munich**, the VLAN **guests** of site
**berlin**.

**otpme-site config berlin vlan_trusts munich:berlin/guests**  
Berlin answers for its network, so **berlin** has to agree: objects of
**munich** may get **guests**, and no other VLAN of **berlin**.

# AUTH ON ACTION HOOKS

An auth on action policy can ask for a login again before these actions.
See **Auth On Action Policy** in **otpme-policy**(1). A vlan has the
hooks every object type has, and these; a command of another name is in
brackets:

> add_device, add_host, add_role, add_token, change_vlan_id (vlan_id),
> remove_device, remove_host, remove_role, remove_token,
> set_config_parameter (config).

# FILES

*/var/lib/otpme/tree/*  
The objects of the realm. A VLAN is the directory *\<name\>.vlan* in the
directory of its unit, e.g.
*\<realm\>.realm/\<site\>.site/vlans.unit/guests.vlan/*, with its
settings in *object.json*, on the nodes of every site, never on a host.
Change them with the commands above, not in the files.

# SEE ALSO

**otpme**(1), **otpme**(7), **otpme-site**(1), **otpme-unit**(1),
**otpme-role**(1), **otpme-token**(1), **otpme-host**(1),
**otpme-device**(1), **otpme-policy**(1), **otpme-trash**(1),
**otpme-tool**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
