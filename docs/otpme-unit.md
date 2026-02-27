# NAME

otpme-unit - manage OTPme organizational units

# SYNOPSIS

**otpme-unit** *command* \[*options*\] \[*unit*\]

# DESCRIPTION

**otpme-unit** manages organizational units in the OTPme system. Units
provide a hierarchical structure for organizing objects such as users
and groups.

# COMMANDS

## Unit Management

**add *unit***  
Add a new unit.

**del *unit***  
Delete a unit.

**show \[*unit*\]**  
Display unit information.

**list \[*regex*\]**  
List units, optionally filtered by regex pattern.

**enable *unit***  
Enable a disabled unit.

**disable *unit***  
Disable a unit without deleting it.

**rename *unit* *new_name***  
Rename a unit.

**move \[**-m**\] \[**-k**\] \[**-o** *object_types*\] \[**--keep-acls**\] *unit* *new_unit***  
Move unit to a different unit. Use **-m** to merge objects into
destination, **-k** to keep source unit.

**touch *unit***  
Re-index the object to fix potential index problems.

## Unit Configuration

**config \[**-d**\] *unit* *parameter* \[*value*\]**  
Set or display a configuration parameter. Use **-d** to delete (reset to
default).

**show_config *unit* \[*parameter*\]**  
Show unit config parameters.

**description *unit* \[*description*\]**  
Set unit description.

## Policy Management

**add_policy *unit* *policy***  
Add policy to unit.

**remove_policy *unit* *policy***  
Remove policy from unit.

**list_policies \[*unit*\]**  
List assigned policies.

## ACL Management

**add_acl \[**-r**\] \[**-a**\] \[**--objects** *types*\] *unit* *owner_type* *owner* *acl***  
Add an access control entry. Use **-r** for recursive, **-a** to apply
default ACLs to existing objects.

**del_acl \[**-r**\] \[**-a**\] \[**--objects** *types*\] *unit* *acl***  
Remove an access control entry.

**show_acls *unit***  
Display all ACLs for the unit.

**enable_acl_inheritance *unit***  
Enable ACL inheritance from parent objects.

**disable_acl_inheritance *unit***  
Disable ACL inheritance.

## Extension and Attribute Management

**add_extension *unit* *extension***  
Add an extension to the unit.

**remove_extension *unit* *extension***  
Remove an extension from the unit.

**add_attribute *unit* *attribute*=*value***  
Add an LDAP attribute to the unit.

**modify_attribute *unit* *attribute* *old_value* *new_value***  
Modify an LDAP attribute of the unit.

**del_attribute *unit* *attribute*=*value***  
Delete an LDAP attribute from the unit.

**add_object_class *unit* *class***  
Add an LDAP object class to the unit.

**del_object_class *unit* *class***  
Delete an LDAP object class from the unit.

**show_ldif \[**-a** *attributes*\] *unit***  
Show LDIF representation of the unit. Use **-a** to show only specific
attributes.

## Import/Export

**export \[**--password** *password*\] *unit***  
Export unit config to stdout.

**remove_orphans \[**-r**\] *unit***  
Remove orphan UUIDs. Use **-r** for recursive.

# OPTIONS

## Display Options

**-a**  
Show all units.

**-z *SIZE***  
Limit output size.

**--fields *FIELD1,FIELD2***  
Display only specified fields.

**--policy-limit *N***  
Limit number of policies shown.

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

## Move Options

**-m**  
Merge objects from source unit into destination unit.

**-k**  
Keep source unit.

**--keep-acls**  
Keep object ACLs.

**-o *user,group,...***  
Move only given object types.

## General Options

**-r**  
Recursive (for ACL and remove_orphans operations).

**-a**  
Apply default ACLs to existing objects (for ACL operations).

**--objects *type1,type2***  
Limit ACL operations to specific object types.

**--password *PASS***  
Password for encrypting exports.

Global options are available for all commands. See **otpme**(1) for
details.

# CONFIG PARAMETERS

Configuration parameters can be set with the **config** command and
displayed with **show_config**. For a complete description of all
available parameters and their applicable object types, see
**otpme**(7).

# EXAMPLES

**otpme-unit add it**  
Create a new unit

**otpme-unit add it/admins**  
Create a sub-unit

**otpme-unit move -m old_unit new_unit**  
Merge objects from old_unit into new_unit

# FILES

*/var/lib/otpme/*  
OTPme data directory

# SEE ALSO

**otpme**(1), **otpme**(7), **otpme-user**(1), **otpme-group**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
