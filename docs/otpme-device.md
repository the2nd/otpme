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
access group with **otpme-accessgroup**(1).

# COMMANDS

## Device Management

**add *device***  
Create a new device.

**del *device***  
Delete a device.

**show \[*device*\]**  
Display device information.

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

## MAC Address

**mac *device* *mac_address***  
Set the MAC address of the device. The MAC address is used for MAB port
authentication.

## Configuration

**config \[**-d**\] \[**-a**\] *device* *parameter* \[*value*\]**  
Set a configuration parameter. Use **-d** to delete (reset to default),
**-a** to append a value.

**show_config *device* \[*parameter*\]**  
Show all configuration parameters.

**description *device* \[*description*\]**  
Set device description.

## Policy Management

**add_policy *device* *policy***  
Attach a policy to the device.

**remove_policy *device* *policy***  
Remove a policy from the device.

**list_policies *device***  
List policies attached to the device.

## ACL Management

**add_acl *device* *owner_type* *owner* *acl***  
Add an access control entry.

**del_acl *device* *acl***  
Remove an access control entry.

**show_acls *device***  
Display all ACLs for the device.

**enable_acl_inheritance *device***  
Enable ACL inheritance from parent objects.

**disable_acl_inheritance *device***  
Disable ACL inheritance.

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

**--token-limit *N***  
Limit number of tokens shown.

**--role-limit *N***  
Limit number of roles shown.

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
Display specific attribute in list command.

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

**otpme-device description ip-phone-1 Reception IP Phone**  
Set description

**otpme-device show ip-phone-1**  
Show device details

# FILES

*/var/lib/otpme/*  
OTPme data directory

# SEE ALSO

**otpme**(7), **otpme-accessgroup**(1), **otpme-host**(1),
**otpme-client**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
