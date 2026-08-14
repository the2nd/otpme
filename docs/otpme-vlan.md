# NAME

otpme-vlan - manage OTPme VLANs

# SYNOPSIS

**otpme-vlan** *command* \[*options*\] \[*vlan*\]

# DESCRIPTION

**otpme-vlan** manages VLAN objects in the OTPme system. A VLAN object
is the assignable representation of a network VLAN. Its value is
returned as **Tunnel-Private-Group-Id** during 802.1x or MAB port
authentication.

There are two ways to assign a VLAN. The VLAN can be named on the
object, through the **vlans** config parameter of sites, units, hosts,
devices, users and tokens. Or the object can be named on the VLAN, by
adding it as a member with **add_token**, **add_role**, **add_host** or
**add_device**.

Membership is the way to keep assignments where the network is. It only
ever applies to VLANs of the site answering the RADIUS request, so a
site makes all of its own assignments without touching objects that are
owned somewhere else, and without any of the cross site rules further
down: the member list lives on the VLAN object, which only its own site
can edit. Member lists are not synced to other sites.

The more specific assignment wins. A VLAN naming the object itself comes
first, then one naming a role the object is in, then one naming a role
that role is in, and so on up the nesting. So a single token can be
moved out of the VLAN of its role, and a role nested in another can have
a VLAN of its own. All of them win over the **vlans** config parameter,
which is only looked at when no VLAN of our site names the object.

Where two VLANs name the object at the same distance -- it is in two
roles of the same nesting level, each in a different VLAN -- there is
nothing to tell them apart. The VLAN whose name sorts first is used, so
the answer is at least the same every time, and a warning naming both is
logged.

An object can only be a member of one VLAN per site. Adding it to a
second one is refused, naming the VLAN it is already in. Only membership
entered directly counts here: a role in another VLAN is not a conflict,
it is what a more specific entry is meant to override.

The rest of this section is about the **vlans** config parameter.
Assigning a VLAN that way requires the **assign** ACL on the VLAN
object. This makes VLAN assignment delegable per VLAN: an operator can
be allowed to hand out the guest VLAN without being able to put anybody
into the server VLAN.

VLANs are site local objects, but they can be assigned across sites by
prefixing the site name (*site***/***vlan*). This is needed when users
are created on the master site only while each site runs its own VLANs.

An object can have one VLAN per site assigned, because an object may be
used at more than one site. The site answering the RADIUS request
returns its own VLAN. If none of the assigned VLANs belongs to it, it
returns the first one its **vlan_trusts** allow, in the order of those
entries.

A cross site assignment is honoured only if the site answering the
RADIUS request lists it under **vlan_trusts**, as
*site*\[**:***vlan_site*\[**/***vlan*\]\] (see **otpme**(7)). The VLAN
is switched in that site's network, whichever site owns the VLAN object,
so that site decides. The **assign** ACL alone is not enough here,
because it is checked by the site making the assignment against its own
copy of the VLAN, so a site holding the users cannot put them into a
VLAN of a network that did not agree.

A VLAN object carries an optional VLAN ID. If a VLAN ID is set it is
sent to the switch. Without a VLAN ID the VLAN name is sent instead,
which is what switches configured with named VLANs (e.g. Cisco) expect.

# COMMANDS

## VLAN Management

**add *vlan* \[*vlan_id*\]**  
Create a new VLAN, optionally with a VLAN ID.

**del *vlan***  
Delete a VLAN. Asks for confirmation according to the confirmation
policy, saying how many members it still has. Members lose their VLAN
with it, nothing is left behind. Objects that name the VLAN in their
**vlans** config parameter keep an unresolvable assignment, they are not
listed because that parameter is not indexed.

**show \[*vlan*\]**  
Display VLAN information.

**list \[*regex*\]**  
List VLANs, optionally filtered by regex pattern.

**enable *vlan***  
Enable a disabled VLAN. A disabled VLAN is not handed out on
authentication.

**disable *vlan***  
Disable a VLAN without deleting it.

**rename *vlan* *new_name***  
Rename a VLAN. Existing assignments are kept, because they reference the
VLAN by UUID.

**move \[**--keep-acls**\] *vlan* *unit***  
Move VLAN to a different unit.

**touch *vlan***  
Re-index the object to fix potential index problems.

## Members

**add_token *vlan* *user***/***token***  
Add a token to the VLAN. Refused if the token is already a member of
another VLAN of this site.

**remove_token *vlan* *user***/***token***  
Remove a token from the VLAN.

**add_role *vlan* *role***  
Add a role to the VLAN. Every token, host and device of the role is then
in the VLAN, and so is every role nested in it, unless a VLAN names one
of them more closely.

**remove_role *vlan* *role***  
Remove a role from the VLAN.

**add_host *vlan* *host***  
Add a host to the VLAN. Used for MAB port authentication.

**remove_host *vlan* *host***  
Remove a host from the VLAN.

**add_device *vlan* *device***  
Add a device to the VLAN. Used for MAB port authentication.

**remove_device *vlan* *device***  
Remove a device from the VLAN.

## VLAN ID

**vlan_id *vlan* \[*vlan_id*\]**  
Set the 802.1Q VLAN ID (1-4094). Without *vlan_id* the VLAN ID is
removed and the VLAN name is sent to the switch instead.

## Policy Management

**add_policy *vlan* *policy***  
Attach a policy to the VLAN.

**remove_policy *vlan* *policy***  
Remove a policy from the VLAN.

**list_policies *vlan***  
List policies attached to the VLAN.

## ACL Management

**add_acl *vlan* *owner_type* *owner* *acl***  
Add an access control entry. Use the **assign** ACL to allow assigning
this VLAN to other objects.

**del_acl *vlan* *acl***  
Remove an access control entry.

**show_acls *vlan***  
Display all ACLs for the VLAN.

**enable_acl_inheritance *vlan***  
Enable ACL inheritance from parent objects.

**disable_acl_inheritance *vlan***  
Disable ACL inheritance.

## Configuration

**config \[**-a**\] \[**-d**\] *vlan* *parameter* \[*value*\]**  
Set, append to or delete a config parameter.

**get_config *vlan* *parameter***  
Show a config parameter.

**description *vlan* \[*description*\]**  
Set VLAN description.

**info \[**--language** *LANG*\] *vlan* \[*info*\]**  
Set free-form info text. If *info* is omitted, the current info text is
opened in the editor specified by the **EDITOR** environment variable.

**dump_info \[**--language** *LANG*\] *vlan***  
Dump the info text to stdout.

## Import/Export

**export \[**--password** *PASS*\] *vlan***  
Export VLAN configuration.

**remove_orphans *vlan***  
Remove orphaned object references.

# OPTIONS

## Display Options

**-a**  
Show all VLANs.

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
Preserve ACLs when moving VLAN.

**--password *PASS***  
Password for encrypting exports.

Global options are available for all commands. See **otpme**(1) for
details.

# EXAMPLES

**otpme-vlan add guests 100**  
Create a VLAN with VLAN ID 100

**otpme-vlan add printers**  
Create a VLAN without a VLAN ID. The name "printers" is sent to the
switch.

**otpme-vlan vlan_id guests 110**  
Change the VLAN ID

**otpme-vlan add_acl guests role netadmins assign**  
Allow the role "netadmins" to assign this VLAN

**otpme-vlan add_role guests employees**  
Put every token, host and device of the role "employees" into the VLAN

**otpme-vlan add_token servers joe/login**  
Put a single token into another VLAN, no matter which VLAN its roles are
in

**otpme-vlan add_role servers admins**  
Give a role nested in "employees" a VLAN of its own. Its members get it
instead of the VLAN of "employees", which stays with everyone else

**otpme-vlan add_host printers hp-lj-01**  
Put a host into the VLAN, for MAB port authentication

**otpme-token config joe/login vlans guests**  
Assign the VLAN to a token

**otpme-host config myhost vlans berlin/guests**  
Assign a VLAN of another site to a host

**otpme-site config berlin vlan_trusts master:berlin/guests**  
Allow objects of the site "master" to get the VLAN "guests" of berlin

# FILES

*/var/lib/otpme/*  
OTPme data directory

# SEE ALSO

**otpme**(1), **otpme**(7), **otpme-token**(1), **otpme-host**(1),
**otpme-device**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
