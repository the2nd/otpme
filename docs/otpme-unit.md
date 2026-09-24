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

**move \[**-m**\] \[**-k**\] \[**-o** *object_types*\] \[**--keep-acls**\] \[**--skip-ca**\] *unit* *new_unit***  
Move unit to a different unit. Use **-m** to merge objects into
destination, **-k** to keep source unit. A CA cannot be moved: with
**--skip-ca** everything else is moved and the source unit is kept. This
is not the same as **-f**, which only skips the confirmation.

**touch *unit***  
Re-index the object to fix potential index problems.

## Unit Configuration

**config \[**-d**\] \[**-a**\] *unit* *parameter* \[*value*\]**  
Set a configuration parameter. Use **-d** to delete (reset to default)
or **-a** to append the value to a list-typed parameter.

**show_config *unit* \[*parameter*\]**  
Show unit config parameters.

**get_config *unit* *parameter***  
Show the value of a single configuration parameter.

**description *unit* \[*description*\]**  
Set unit description.

**info \[**--language** *LANG*\] *unit* \[*info*\]**  
Set free-form info text. If *info* is omitted, the current info text is
opened in the editor specified by the **EDITOR** environment variable.

**dump_info \[**--language** *LANG*\] *unit***  
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

**changelog *unit***  
Show the changelog of the unit. Needs the ACL **view:changelog**.

**edit_changelog *unit* *entry_id* *comment***  
Set the comment of that entry, or replace the one it has. Needs the ACL
**edit:changelog**.

**del_changelog *unit* *entry_id***  
Remove the comment of that entry. The entry itself stays, and an entry
without a comment is refused. Needs the ACL **edit:changelog**.

**clear_changelog *unit***  
Remove every entry of the changelog.  
This needs more than the ACL **clear:changelog**: the config parameter
**allow_changelog_clearing** has to allow it (see **otpme**(7)). It is
true by default, but where no value is found at all, clearing is
refused. OTPme asks the token you are signed in with first, then the
object.

## Policy Management

A *policy* is the name of a policy, not a path. It is looked for in the
site of the unit. Which policies there are, and what each of them does,
is in **otpme-policy**(1).

Attaching and detaching ask before they change anything; the global
option **-f** skips the question.

**add_policy *unit* *policy***  
Attach a policy to the unit.  
A policy has a list of object types it is for; one that does not name
**unit** is refused. So is a second policy of a type that allows only
one per object.  
Needs the ACL **assign:policy**.

**remove_policy *unit* *policy***  
Remove a policy from the unit.  
Needs the ACL **remove:policy**, and that one verbatim: a plain
**remove** does not cover it. Detaching a policy takes away what it
enforces, so it must not be cheaper than attaching one.

**list_policies \[**--return-type** *TYPE*\] \[**--policy-types** *t1,t2*\] *unit***  
List the policies attached to the unit. Use **--return-type** to select
the attribute returned (**name**, **read_oid**, **full_oid**, **uuid**).
Use **--policy-types** to list only policies of the given types; these
are policy types, not policy names.  
Needs the ACL **view:policies**.

## ACL Management

**add_acl \[**-r**\] \[**-a**\] \[**--objects** *types*\] *unit* *owner_type* *owner* *acl***  
Add an access control entry. Use **-r** for recursive, **-a** to apply
default ACLs to existing objects.

**del_acl \[**-r**\] \[**-a**\] \[**--objects** *types*\] *unit* *acl***  
Remove an access control entry.

**list_acls *unit***  
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
