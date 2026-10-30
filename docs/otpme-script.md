# NAME

otpme-script - manage OTPme scripts

# SYNOPSIS

**otpme-script** *command* \[*options*\] \[*script*\]

# DESCRIPTION

**otpme-script** manages scripts in the OTPme system. Scripts are stored
as OTPme objects and can be signed to ensure integrity. They are used
for various purposes such as login scripts and key scripts.

# COMMANDS

## Script Management

**add \[**-r**\] *name* *script***  
Add a new script. Use **-r** to replace an existing script while keeping
its UUID.

**del *script***  
Delete a script.

**show \[*script*\]**  
Display script information.

<!-- -->

**show_oid \[**--full**\] *script***  
Show the OID of the script:
**script\|\<realm\>/\<site\>/\<unit_path\>/\<name\>**. **--full** is
accepted and shows the same.  
Needs the ACL **view_public:object**.

**show_uuid *script***  
Show the UUID of the script.  
Needs the ACL **view_public:object**.

<!-- -->

**list \[*regex*\]**  
List scripts, optionally filtered by regex pattern.

**enable *script***  
Enable a disabled script.

**disable *script***  
Disable a script without deleting it.

**rename *script* *new_name***  
Rename a script.

**copy *script* *dst_script***  
Copy a script and its signatures.

**move \[**--keep-acls**\] *script* *unit***  
Move script to a different unit.

**touch *script***  
Re-index the object to fix potential index problems.

**auto_disable *script* *time***  
Set auto-disable time. It is either a relative time with a leading
**+**, e.g. **+30D**, or an absolute one, e.g. **"09:53 13.06.2023"**.
The units are **s**, **m**, **h**, **D**, **W**, **M** and **Y**, see
**otpme**(7). A relative time counts from when it is set, and again from
when the script is enabled. **0** removes it. It is refused for an
object the realm or a site comes with, e.g. the admin user; a time set
on one before does nothing.

## Script Operations

**dump *script***  
Dump script contents to stdout.

**edit *script***  
Edit a script.

**run \[**--type** *script_type*\] *script***  
Run a script. Use **--type** to run as a specific script type (e.g.
key_script).

## Signature Management

**sign \[**--stdin-pass**\] \[**--tags** *tag1,tag2*\] *script***  
Sign a script. Use **--stdin-pass** to read the RSA private key
passphrase from stdin.

**resign \[**--stdin-pass**\] *script***  
Re-sign all script signatures.

**verify_sign \[**--user** *username*\] \[**--tags** *tag1,tag2*\] *script***  
Verify script signature(s).

**get_sign \[**--user** *username*\] \[**--tags** *tag1,tag2*\] *script***  
Get script signature(s).

**get_sign_data \[**--tags** *tag1,tag2*\] *script***  
Get the data to be signed from a script.

**add_sign \[**--tags** *tag1,tag2*\] *script* *signature***  
Add a signature to a script.

**del_sign \[**--user** *username*\] \[**--tags** *tag1,tag2*\] *script***  
Delete a signature from a script.

## Policy Management

A *policy* is the name of a policy, not a path. It is looked for in the
site of the script. Which policies there are, and what each of them
does, is in **otpme-policy**(1).

Attaching and detaching ask before they change anything; the global
option **-f** skips the question.

**add_policy *script* *policy***  
Attach a policy to the script.  
A policy has a list of object types it is for; one that does not name
**script** is refused. So is a second policy of a type that allows only
one per object.  
Needs the ACL **assign:policy**.

**remove_policy *script* *policy***  
Remove a policy from the script.  
Needs the ACL **remove:policy**, and that one verbatim: a plain
**remove** does not cover it. Detaching a policy takes away what it
enforces, so it must not be cheaper than attaching one.

**list_policies \[**--return-type** *TYPE*\] \[**--policy-types** *t1,t2*\] *script***  
List the policies attached to the script, the disabled ones too, marked
**(disabled)**. Use **--return-type** to select the attribute returned
(**name**, **read_oid**, **full_oid**, **uuid**). Use **--policy-types**
to list only policies of the given types; these are policy types, not
policy names.  
Needs the ACL **view:policies**.

## ACL Management

**add_acl *script* *owner_type* *owner* *acl***  
Add an access control entry.

**del_acl *script* *acl***  
Remove an access control entry.

**list_acls *script***  
Display all ACLs for the script.

**enable_acl_inheritance *script***  
Let a move of the script swap its default ACLs: what the old unit handed
down is taken away, and what the new unit hands down is given. It does
not by default; a move then leaves the ACLs of the script as they are.

Only a move asks this. A new script gets the default ACLs of its unit,
and **add_acl -a** or **-r** on a unit reach it either way. A move with
**--keep-acls** leaves its ACLs alone all the same.

A move by somebody who does not hold **add:acl** and **delete:acl** on
the script leaves its ACLs alone as well, and says so. Otherwise moving
an object into a unit would be a way of handing yourself the default
ACLs of that unit.

Needs the ACL **enable:acl_inheritance**.

**disable_acl_inheritance *script***  
A move leaves the ACLs of the script as they are again.  
Needs the ACL **disable:acl_inheritance**.

## Configuration

**description *script* \[*description*\]**  
Set script description.

**info \[**--language** *LANG*\] *script* \[*info*\]**  
Set free-form info text. If *info* is omitted, the current info text is
opened in the editor specified by the **EDITOR** environment variable.

**dump_info \[**--language** *LANG*\] *script***  
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

**changelog *script***  
Show the changelog of the script. Needs the ACL **view:changelog**.

**edit_changelog *script* *entry_id* *comment***  
Set the comment of that entry, or replace the one it has. Needs the ACL
**edit:changelog**.

**del_changelog *script* *entry_id***  
Remove the comment of that entry. The entry itself stays, and an entry
without a comment is refused. Needs the ACL **edit:changelog**.

**clear_changelog *script***  
Remove every entry of the changelog.  
This needs more than the ACL **clear:changelog**: the config parameter
**allow_changelog_clearing** has to allow it (see **otpme**(7)). It is
true by default, but where no value is found at all, clearing is
refused. A value set on the token you are signed in with counts first.
Without one, the value of the object counts, read along its cascade.

## Import/Export

**export \[**--password** *PASS*\] *script***  
Export script configuration.

**remove_orphans *script***  
Remove orphaned object references.

# OPTIONS

## Display Options

**-a**  
Show all scripts.

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

**-r**  
Replace existing script and keep its UUID.

**--keep-acls**  
Preserve ACLs when moving script.

**--password *PASS***  
Password for encrypting exports.

**--stdin-pass**  
Read RSA private key passphrase from stdin.

**--tags *tag1,tag2***  
Tags for signatures.

**--user *username***  
Select signature by username.

Global options are available for all commands. See **otpme**(1) for
details.

# EXAMPLES

**otpme-script add myscript /path/to/script.sh**  
Add a new script

**otpme-script sign myscript**  
Sign a script

**otpme-script dump myscript**  
Show script contents

**otpme-script edit myscript**  
Edit a script

# AUTH ON ACTION HOOKS

An auth on action policy can ask for a login again before these actions.
See **Auth On Action Policy** in **otpme-policy**(1). A script has the
hooks every object type has, and these:

> add_sign, del_sign, set_config_parameter, show_config_parameters,
> sign.

# FILES

*/var/lib/otpme/*  
OTPme data directory

# SEE ALSO

**otpme**(1), **otpme**(7), **otpme-acls**(7), **otpme-user**(1),
**otpme-token**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
