# NAME

otpme-device - manage OTPme network devices for MAB port authentication

# SYNOPSIS

**otpme-device** *command* \[*options*\] \[*device*\]

# DESCRIPTION

**otpme-device** manages network devices in the OTPme system. Devices
represent network equipment such as IP phones or printers that
authenticate via MAC Authentication Bypass (MAB). Each device has a MAC
address and can be assigned to an access group to control network
access.

To use a device for MAB port authentication, add it with
**otpme-device**, set its MAC address and add it to the appropriate
access group with **otpme-accessgroup**(1). A VLAN can be assigned on
top of that, see **VLAN Assignment** below.

# COMMANDS

## Device Management

**add *device***  
Create a new device.

**del *device***  
Delete a device. The passwords of the device stay; the question says how
many there are.

**show \[*device*\]**  
Display device information.

<!-- -->

**show_oid \[**--full**\] *device***  
Show the OID of the device: **device\|\<realm\>/\<site\>/\<name\>**.
With **--full** the full OID, which names the unit as well:
**device\|\<realm\>/\<site\>/\<unit_path\>/\<name\>**.  
Needs the ACL **view_public:object**.

**show_uuid *device***  
Show the UUID of the device.  
Needs the ACL **view_public:object**.

<!-- -->

**list \[*regex*\]**  
List devices, optionally filtered by regex pattern.

**enable *device***  
Enable a disabled device.

**disable *device***  
Disable a device without deleting it.

**touch *device***  
Re-index the device to fix potential index problems.

**move \[**--keep-acls**\] *device* *unit***  
Move device to a different unit.

**auto_disable \[**-u**\] *device* *time***  
Set auto-disable time. It is either a relative time with a leading
**+**, e.g. **+30D**, or an absolute one, e.g. **"09:53 13.06.2023"**.
The units are **s**, **m**, **h**, **D**, **W**, **M** and **Y**, see
**otpme**(7). A relative time counts from when it is set, and again from
when the device is enabled. **0** removes it. It is refused for an
object the realm or a site comes with, e.g. the admin user; a time set
on one before does nothing. Use **-u** to disable the device once it was
unused for the given time. That takes a relative time; a device that was
never used counts from when this was set.

## MAC Address

**mac *device* *mac_address***  
Set the MAC address of the device. The MAC address is used for MAB port
authentication.

## VLAN Assignment

A device is not assigned a VLAN from here. Either the VLAN names the
device, so that the assignment belongs to the site that runs the network
(see **otpme-vlan**(1)):

> **otpme-vlan add_device *vlan* *device***

or the device names the VLAN through its **vlans** config parameter (see
**otpme**(7)):

> **otpme-device config *device* vlans *vlan***

The VLAN is returned during MAB port authentication, together with the
access granted through the access group. Membership wins: the **vlans**
parameter is only looked at when no VLAN of the site answering the
RADIUS request names the device. A device that is in a VLAN only through
a role is overridden by one that names the device itself.

## Passwords

Passwords can belong to the device, for example the admin password of a
switch, see **otpme-pass**(1). Each password decides itself whether you
may see it.

**find_passwords \[**--return-type** *TYPE*\] *device***  
The password objects that belong to the device.

**show_password *device* \[*entry*\]**  
Show the entries of these passwords, with their passwords. With *entry*
only the entries of that name.  
Each password needs **view:entries**, and you need a key for it.

## Configuration

**config \[**-d**\] \[**-a**\] *device* *parameter* \[*value*\]**  
Set a configuration parameter. Use **-d** to delete (reset to default),
**-a** to append a value.

**show_config *device* \[*parameter*\]**  
Show all configuration parameters.

**get_config *device* *parameter***  
Show the value of a single configuration parameter.

**description *device* \[*description*\]**  
Set device description.

**info \[**--language** *LANG*\] *device* \[*info*\]**  
Set free-form info text. If *info* is omitted, the current info text is
opened in the editor specified by the **EDITOR** environment variable.

**dump_info \[**--language** *LANG*\] *device***  
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

**changelog *device***  
Show the changelog of the device. Needs the ACL **view:changelog**.

**edit_changelog *device* *entry_id* *comment***  
Set the comment of that entry, or replace the one it has. Needs the ACL
**edit:changelog**.

**del_changelog *device* *entry_id***  
Remove the comment of that entry. The entry itself stays, and an entry
without a comment is refused. Needs the ACL **edit:changelog**.

**clear_changelog *device***  
Remove every entry of the changelog.  
This needs more than the ACL **clear:changelog**: the config parameter
**allow_changelog_clearing** has to allow it (see **otpme**(7)). It is
true by default, but where no value is found at all, clearing is
refused. A value set on the token you are signed in with counts first.
Without one, the value of the object counts, read along its cascade.

## Policy Management

A *policy* is the name of a policy, not a path. It is looked for in the
site of the device. Which policies there are, and what each of them
does, is in **otpme-policy**(1).

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

**list_policies \[**--return-type** *TYPE*\] \[**--policy-types** *t1,t2*\] *device***  
List the policies attached to the device, the disabled ones too, marked
**(disabled)**. Use **--return-type** to select the attribute returned
(**name**, **read_oid**, **full_oid**, **uuid**). Use **--policy-types**
to list only policies of the given types; these are policy types, not
policy names.  
Needs the ACL **view:policies**.

## ACL Management

**add_acl *device* *owner_type* *owner* *acl***  
Add an access control entry.

**del_acl *device* *acl***  
Remove an access control entry.

**list_acls *device***  
Display all ACLs for the device.

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

## Import/Export

**export \[**--password** *PASS*\] *device***  
Export device configuration.

**remove_orphans *device***  
Remove orphaned object references.

# OPTIONS

## Display Options

**-a**  
Show all devices (across all units).

**-z *SIZE***  
Limit output size.

**--fields *FIELD1,FIELD2***  
Display only specified fields.

**--policy-limit *N***  
Limit number of policies shown.

**--limit *N***  
Limit number of items shown per object.

<!-- -->

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

**--attribute *ATTR***  
Of **list**: match the regex against this attribute instead of the name.

## General Options

**--keep-acls**  
Preserve ACLs when moving device.

**--password *PASS***  
Password for encrypting exports.

Global options are available for all commands. See **otpme**(1) for
details.

# EXAMPLES

**otpme-device add ip-phone-1**  
Create a device for an IP phone

**otpme-device mac ip-phone-1 90:1b:0e:46:46:15**  
Set the MAC address

**otpme-accessgroup add_device lan ip-phone-1**  
Add device to access group for MAB

**otpme-vlan add_device voice ip-phone-1**  
Put the device into the voice VLAN

**otpme-device description ip-phone-1 "Reception IP Phone"**  
Set description

**otpme-device show ip-phone-1**  
Show device details

# AUTH ON ACTION HOOKS

An auth on action policy can ask for a login again before these actions.
See **Auth On Action Policy** in **otpme-policy**(1). A device has the
hooks every object type has, and no others.

# FILES

*/var/lib/otpme/*  
OTPme data directory

# SEE ALSO

**otpme**(7), **otpme-acls**(7), **otpme-accessgroup**(1),
**otpme-host**(1), **otpme-vlan**(1), **otpme-pass**(1),
**otpme-client**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
