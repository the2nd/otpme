# NAME

otpme-device - manage devices: network equipment that logs in by its MAC
address

# SYNOPSIS

**otpme-device** *command* \[*options*\] \[*device*\]

# DESCRIPTION

**otpme-device** manages the devices of a realm: network equipment such
as IP phones or printers that cannot log in by itself. A device has no
tokens. It logs in by MAC Authentication Bypass (MAB): the switch sends
its MAC address as user name and as password.

Which access group counts is the one of the RADIUS client that asks,
i.e. the switch, see **otpme-client**(1). The device has to be in that
group, directly or through a role in it, see **otpme-accessgroup**(1).
The answer can carry a VLAN, see **VLAN Assignment** below.

A password can belong to the device, for example the admin password of
the phone's web interface, see **Passwords** below.

A new device goes into the unit **devices**, unless a path or a
**defaultunits** policy names another. Its name is unique in the realm.
Devices are kept on the nodes only; a host never gets one.

# COMMANDS

## Device Management

**add *device***  
Add a device. With a path, e.g. **berlin/phone1**, it goes into that
unit; else into the unit a **defaultunits** policy names, see
**otpme-policy**(1), or into **devices**. The name is unique in the
realm, whatever site and unit it is in, as MAB finds a device of any
site; it is taken in lower case. It may be **max_device_name_len** long
(64 by default).  
A new device is enabled and has no MAC address yet, see **mac**. It is
put into the access group of **devices_accessgroup** and into the role
of **devices_role**, where they are set, see **otpme**(7).  
Needs **add:device** on the unit.

**del** \[**--no-trash**\] *device*  
Delete the device. It goes to the trash, see **otpme-trash**(1);
**--no-trash** deletes it right away.  
It is taken out of its access groups and roles. Its passwords stay, see
**otpme-pass**(1); the question says how many there are.  
Needs **delete:object** on the device or **delete:device** on the unit.

**show** \[**-a**\] \[**-z** *N*\] \[**--fields** *F1,F2*\] \[**--limit** *N*\] \[**--role-limit** *N*\] \[**--policy-limit** *N*\] \[**--sort-by** *field*\] \[**--reverse**\] \[**--raw**\] \[**--csv**\] \[**--csv-sep** *sep*\] \[*device*\]  
Without a device: a table of all of them, with their unit, status, MAC
address, roles, access groups, policies, ACL inheritance and
description. The access groups are those the device is in and, in
brackets, those it gets through a role.

**-a**  
Also the devices you may only look at, not just the ones you may change.

**-z *N***  
How many devices to print.

**--fields *F1,F2***  
Print these columns and no others, in the order they are named. A name
with a **+** in front is added to the columns that are shown anyway, and
one with a **-** is left out of them.

**--limit *N***  
How many of each kind to print per device: roles, policies.

**--role-limit *N*, **--policy-limit** *N***  
The same for one of them.

**--sort-by *field*, **--reverse****  
Which column to sort by, and the other way round.

**--raw, **--csv**, **--csv-sep** *sep***  
**--raw** leaves the header and the borders out, **--csv** prints one
row per line with **;** between the columns, and **--csv-sep** uses
another separator.

A column you may not see says **-**. With a device named, this prints
the object itself instead of a table row, one value per line. **show**
***device*$** prints that one device as a table row. A name that is no
device is a pattern with **\***, not a regex, see **SELECTING OBJECTS**
in **otpme**(1).

**show_oid** \[**--full**\] *device*  
Show the OID of the device: **device\|\<realm\>/\<name\>**. With
**--full** the full OID, which names the unit as well:
**device\|\<realm\>/\<site\>/\<unit_path\>/\<name\>**.  
Needs the ACL **view_public:object**.

**show_uuid *device***  
Show the UUID of the device.  
Needs the ACL **view_public:object**.

**list** \[**-a**\] \[**--attribute** *attribute*\] \[*pattern*\]  
List the device names, and with a pattern only those that match it, e.g.
**berlin-\***. You get the devices you may change; **-a** adds those you
may only look at. **--attribute** matches the pattern against that
attribute instead of the name, e.g. **mac_address**.

**enable *device***  
**disable *device***  
A disabled device is refused at MAB, whatever access group it is in.
Tables show the status.  
Needs **enable:object** or **disable:object**.

**rename *device* *new_name***  
Rename the device. The new name must not be in use in the realm, and is
taken in lower case.  
Needs **rename:object**.

**move** \[**--keep-acls**\] *device* *unit*  
Move the device into another unit. The device keeps its ACLs; where ACL
inheritance is on for it (off for devices by default, see
**enable_acl_inheritance**), the default ACLs of the old unit are taken
away and those of the new one given. **--keep-acls** keeps all ACLs as
they are.  
Needs **move** on the device and **add:device** on the unit.

**touch *device***  
Write the index entries of the device again.  
Needs **touch**.

**auto_disable** \[**-u**\] *device* *time*  
Set auto-disable time. It is either a relative time with a leading
**+**, e.g. **+30D**, or an absolute one, e.g. **"09:53 13.06.2023"**.
The units are **s**, **m**, **h**, **D**, **W**, **M** and **Y**, see
**otpme**(7). A relative time counts from when it is set, and again from
when the device is enabled. **0** removes it. Use **-u** to disable the
device once it was unused for the given time; a device is used when it
logs in by MAB. That takes a relative time; a device that was never used
counts from when this was set.  
Needs **edit:auto_disable**.

## MAC Address

**mac *device* *mac_address***  
Set the MAC address of the device. At MAB the switch sends it as the
user name, and the realm finds the device by it; whether the port opens
says its access group, see **otpme-accessgroup**(1).  
Write it as six pairs of hex digits, with **:** or **-** between them,
as three groups of four with **.**, or without anything, e.g.
**00:1a:2b:3c:4d:5e** or **001a2b3c4d5e**. It is kept in lower case with
**:**, and that is how it is shown. The switch may send it in any of
these forms.  
A MAC address can be set on one host or device of the realm only. An
empty *mac_address*, **""**, removes it.  
Needs **edit:mac_address**. Seeing it, with **show**, needs
**view:mac_address**.

## VLAN Assignment

At MAB the realm answers with a VLAN as well, if the device has one. It
is not set here, but in one of two ways.

A VLAN names the device, see **otpme-vlan**(1):

> **otpme-vlan add_device *vlan* *device***

This needs **add:device** on the VLAN. A device can be in one VLAN of a
site only. It can also be in a VLAN through a role it is in; a VLAN that
names the device itself wins over that.

Or the device names the VLAN in its **vlans** config parameter, see
**otpme**(7):

> **otpme-device config *device* vlans *vlan***

This needs **assign** on the VLAN. Where the device has none, it is
taken from the units above it, and else from its site. A VLAN of another
site is written as *\<site\>/\<vlan\>*; it counts only where the
**vlan_trusts** of the site that answers allow it.

Only the VLANs of the site that answers the RADIUS request name a
device. They win: the **vlans** parameter is only looked at when none of
them names the device or a role it is in. A disabled VLAN gives nothing,
and the log says so.

## Passwords

Passwords can belong to the device, for example the admin password of
the phone's web interface. A password is given to it with **otpme-pass
add --device** or **otpme-pass add_device**, see **otpme-pass**(1). Each
password decides itself whether you may see it; the device has no ACL
for that.

**find_passwords** \[**--return-type** *TYPE*\] *device*  
List the passwords that belong to the device and that you may look at,
by **view_public**, **view** or **view:entries** on the password. *TYPE*
is **name** (the default), **read_oid**, **full_oid** or **uuid**. A
name of another site is shown as *\<site\>/\<password\>*.

**show_password *device* \[*entry*\]**  
Show the entries of these passwords, with their passwords. With *entry*
only the entries of that name.  
Each password needs **view:entries**, and you need a key for it.
Passwords you may not read are left out; when none is left, it says so.

## Configuration

A config parameter is looked for on the device, then on the units above
it, then on the site. The first value found is the one that applies, and
the realm holds none. A site can turn that around for a parameter it
names in **force_site_config_parameters,** and then its own value wins
over the device and its units (see **otpme**(7)).

Which parameters a device takes is in **CONFIG PARAMETERS** below.

**config** \[**-d**\] \[**-a**\] *device* *parameter* \[*value*\]  
Set a parameter on the device.

**-d**  
Remove the parameter from the device, or with a value only that one
value from a list. It is not set back to a default: what applies
afterwards is whatever the unit or the site says.

**-a**  
Append the value to a parameter that holds a list, instead of replacing
what is there.

A parameter that devices do not take is refused. The ACL is per
parameter, **set:config:*parameter***. Removing a parameter that is not
registered any more, which is what a rename or a dropped feature leaves
behind, is for admins only.

**show_config *device* \[*parameter*\]**  
The parameters set on the device itself, or only the one named. Nothing
is shown for a parameter that the device gets from a unit or from the
site.  
Each parameter needs **view:config:*parameter***.

**get_config *device* *parameter***  
What the parameter comes to for this device, once the device, its units
and its site have been looked at. So this answers what applies, where
**show_config** answers what was set here.  
Needs **view:config:*parameter***.

**description *device* \[*description*\]**  
Set the description. Without one OTPme asks and offers the current text
for editing.  
Needs **edit:description**.

**info** \[**--language** *LANG*\] *device* \[*info*\]  
Set free-form info text. If *info* is omitted, the current info text is
opened in the editor named by the **EDITOR** environment variable.  
Without **--language** the text is the administrator's own note. Nothing
shows the info of a device to a user, so a text for a language stays a
note as well.  
Needs **edit:info**.

**dump_info** \[**--language** *LANG*\] *device*  
Write one of those texts to stdout, for reading it with something other
than the editor.  
Needs **view:info**.

**show_info** *device*  
List the languages the device has a text for, one per line, with the
first line of the text. The note of the administrator comes first, as
**-**. An empty text is not listed.  
Needs the ACL **view:info**.

## Object Changelog

Every change to the object writes an entry: who made it, when, and what
was done. A change can carry a comment of its own, through the global
option **--changelog**.

The **changelog** config parameter can switch that off. It is read along
the cascade of the device, and nothing is written where it is off — not
for that device, and not for the ones below a unit that switched it off.
Without any value anywhere it is on.

An *entry_id* is the number the listing shows in front of an entry,
counted from 0.

Only the comment of an entry can be changed or removed. What was done
and by whom stays as it is.

A command that changes something asks first; the global option **-f**
skips the question.

**changelog *device***  
Show the changelog of the device, one entry per line: its *entry_id*,
the time, who made the change and what was done, then a detail in round
brackets and the comment in square brackets where there are any. Needs
the ACL **view:changelog**.

**edit_changelog *device* *entry_id* *comment***  
Set the comment of that entry, or replace the one it has. That writes an
entry of its own. Needs the ACL **edit:changelog**.

**del_changelog *device* *entry_id***  
Remove the comment of that entry. The entry itself stays, and an entry
without a comment is refused. That writes an entry of its own. Needs the
ACL **edit:changelog**.

**clear_changelog *device***  
Remove every entry of the changelog. Afterwards it holds one entry: that
it was cleared.  
This needs more than the ACL **clear:changelog**: the config parameter
**allow_changelog_clearing** has to allow it (see **otpme**(7)). It is
true by default, but where no value is found at all, clearing is
refused. A value set on the token you are signed in with counts first.
Without one, the value of the object counts, read along its cascade.

## Policy Management

A *policy* is the name of a policy, not a path. It is looked for in the
site of the device. Which policies there are, and what each of them
does, is in **otpme-policy**(1).

Two types do something on a device: **autodisable** switches it off
after a time, or once it was unused that long (a device is used when it
logs in by MAB), and **authonaction** asks whoever changes the device to
authenticate for it again, see **AUTH ON ACTION HOOKS** below. Every
other type is refused.

Attaching and detaching ask before they change anything; the global
option **-f** skips the question.

**add_policy *device* *policy***  
Attach a policy to the device.  
A policy has a list of object types it is for; one that does not name
**device** is refused. So is a second policy of a type that allows only
one per object.  
Needs the ACL **assign:policy**.

**remove_policy *device* *policy***  
Remove a policy from the device.  
Needs the ACL **remove:policy**, and that one verbatim: a plain
**remove** does not cover it. Detaching a policy takes away what it
enforces, so it must not be cheaper than attaching one.

**list_policies** \[**--return-type** *TYPE*\] \[**--policy-types** *t1,t2*\] *device*  
List the policies attached to the device, the disabled ones too, marked
**(disabled)**. Use **--return-type** to select the attribute returned
(**name**, **read_oid**, **full_oid**, **uuid**). Use **--policy-types**
to list only policies of the given types; these are policy types, not
policy names.  
Needs the ACL **view:policies**.

## ACL Management

An ACL says what somebody may do with this device. The somebody is a
role or a token, never a user.

What the three forms **acl**, **+acl** and **++acl** mean, and which
ACLs exist, is under **ACLs** in **otpme**(7). A device has nothing
below it, so only the plain form is taken; **+acl** and **++acl** are
refused.

A command that changes something asks first; the global option **-f**
skips the question.

**add_acl *device* *owner_type* *owner* *acl*\[:*value*\]\[,*acl*\[:*value*\]\]**  
Give a role or a token one or more ACLs on this device.  
*owner_type* is **role** or **token**. *owner* names it the way
**list_acls** prints it: a role as *site/name*, or by its name alone on
its own site; a token as *user/token*. An ACL can carry a value, for
example **view:mac_address**. To give several ACLs at once, separate
them with commas: **view:mac_address,edit:mac_address**.  
Needs the ACL **add:acl**.

**del_acl *device* *acl*\[,*acl*\]**  
Take those ACLs away again.  
Here an *acl* is the whole entry, owner and all, the way **list_acls**
prints it: **role:berlin/net-admins:view**.  
Needs the ACL **delete:acl**.

**list_acls *device***  
Show the ACLs that lie on this device, i.e. who may do what with it.
Needs the ACL **view:acl**.

**enable_acl_inheritance *device***  
Let a move of the device swap its default ACLs: what the old unit handed
down is taken away, and what the new unit hands down is given. It does
not by default; a move then leaves the ACLs of the device as they are.

Only a move asks this. A new device gets the default ACLs of its unit,
and **add_acl -a** or **-r** on a unit reach it either way. A move with
**--keep-acls** leaves its ACLs alone all the same.

A move by somebody who does not hold **add:acl** and **delete:acl** on
the device leaves its ACLs alone as well, and says so. Otherwise moving
an object into a unit would be a way of handing yourself the default
ACLs of that unit.

Needs the ACL **enable:acl_inheritance**.

**disable_acl_inheritance *device***  
A move leaves the ACLs of the device as they are again.  
Needs the ACL **disable:acl_inheritance**.

## Export and Cleanup

Both write to stdout. There is no import on this page: reading an export
back in is **otpme-tool import,** see **otpme-tool**(1).

**remove_orphans** asks before it changes anything; the global option
**-f** skips the question.

**export** \[**--password** *password*\] *device*  
Write the whole object of the device to stdout, as JSON.

Without **--password** it is written as it is, in clear. With one, a key
is derived from that password and the object is encrypted with it; the
salt goes into the output, so the password is all you need to read it
back.

Its roles and access groups are not in it: they hold the device, not the
other way round.

Needs the ACL **export**.

**remove_orphans *device***  
Remove what the device still points at although it is gone: its ACLs,
its policies and its signatures. Config parameters set on the device
that keep other objects lose the ones that are gone, e.g. a deleted VLAN
in **vlans**, the way **config -d** does.

It shows everything it found and asks once for all of it. It asks
nothing and changes nothing when it finds nothing.

Needs the ACL **remove:orphans**.

# OPTIONS

Every option belongs to one command and is described with that command
above. A short option means what that command makes of it.

Global options work with every command, see **otpme**(1).

# CONFIG PARAMETERS

Each parameter is described with the thing it is about: **vlans** under
**VLAN Assignment**, and **changelog** and **allow_changelog_clearing**
under **Object Changelog**. What each of them does is in **otpme**(7).

# EXAMPLES

The examples use the site **berlin** of the realm **example.org** and an
IP phone called **ip-phone-1**.

## A phone on a MAB port

**otpme-device add ip-phone-1**  
Create the device. Where **devices_accessgroup** is set, it is in that
access group already.

**otpme-device mac ip-phone-1 00:1a:2b:3c:4d:5e**  
The address the switch sends at MAB.

**otpme-accessgroup add_device lan ip-phone-1**  
Let it in through the access group **lan**, where
**devices_accessgroup** does not do it.

**otpme-vlan add_device voice ip-phone-1**  
Put it into the VLAN **voice**.

**otpme-device config ip-phone-1 vlans voice**  
The other way: the device names the VLAN. A VLAN that names the device
wins over this.

**otpme-device description ip-phone-1 "Reception phone"**  
A text to find it by.

## Looking it up

**otpme-device show ip-phone-1**  
The device itself, one value per line.

**otpme-device show ip-phone-1$**  
The same device as a row of the table.

**otpme-device list "ip-phone-\*"**  
The names of all phones.

# AUTH ON ACTION HOOKS

An auth on action policy can ask for a login again before these actions.
See **Auth On Action Policy** in **otpme-policy**(1). A device has the
hooks every object type has, and these; a command of another name is in
brackets:

> change_mac (mac).

# FILES

*/var/lib/otpme/tree/*  
The objects of the realm, on the nodes; devices are not synced to hosts.
A device is the directory *\<device\>.device* in the directory of its
unit, e.g.
*\<realm\>.realm/\<site\>.site/devices.unit/ip-phone-1.device/*, with
its settings in *object.json*. Change them with the commands above, not
in the file.

# SEE ALSO

**otpme**(1), **otpme**(7), **otpme-accessgroup**(1), **otpme-vlan**(1),
**otpme-role**(1), **otpme-client**(1), **otpme-host**(1),
**otpme-pass**(1), **otpme-policy**(1), **otpme-tool**(1),
**otpme-trash**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
