# NAME

otpme-vlan - manage OTPme VLANs

# SYNOPSIS

**otpme-vlan** *command* \[*options*\] \[*vlan*\]

# DESCRIPTION

**otpme-vlan** manages VLAN objects in the OTPme system. A VLAN object
is the assignable representation of a network VLAN. It is referenced by
the **vlans** config parameter of sites, units, hosts, devices, users
and tokens, and the resulting value is returned as
**Tunnel-Private-Group-Id** during 802.1x or MAB port authentication.

Assigning a VLAN requires the **assign** ACL on the VLAN object. This
makes VLAN assignment delegable per VLAN: an operator can be allowed to
hand out the guest VLAN without being able to put anybody into the
server VLAN.

VLANs are site local objects, but they can be assigned across sites by
prefixing the site name (*site***/***vlan*). This is needed when users
are created on the master site only while each site runs its own VLANs.

An object can have one VLAN per site assigned, because an object may be
used at more than one site. The site answering the RADIUS request
returns its own VLAN. If none of the assigned VLANs belongs to it, no
VLAN is returned, unless it lists the VLAN owning site under
**use_vlans_from**.

A cross site assignment additionally requires the VLAN owning site to
list the assigning site under **vlan_trusts**. The **assign** ACL alone
is not enough here, because it is checked by the site making the
assignment against its own copy of the VLAN. The trust check is enforced
again when the VLAN is resolved, on the site that answers the RADIUS
request, so a site holding the users cannot put them into a VLAN of a
network that did not agree.

A VLAN object carries an optional VLAN ID. If a VLAN ID is set it is
sent to the switch. Without a VLAN ID the VLAN name is sent instead,
which is what switches configured with named VLANs (e.g. Cisco) expect.

# COMMANDS

## VLAN Management

**add *vlan* \[*vlan_id*\]**  
Create a new VLAN, optionally with a VLAN ID.

**del *vlan***  
Delete a VLAN.

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

**otpme-token config joe/login vlan guests**  
Assign the VLAN to a token

**otpme-host config myhost vlan berlin/guests**  
Assign a VLAN of another site to a host

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
