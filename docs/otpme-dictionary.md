# NAME

otpme-dictionary - manage OTPme dictionaries

# SYNOPSIS

**otpme-dictionary** *command* \[*options*\] \[*dictionary*\]

# DESCRIPTION

**otpme-dictionary** manages dictionaries in the OTPme system.
Dictionaries are word lists used by password policies for password
strength checking and passphrase generation. Supported dictionary types
are **list**, **sorted-list**, and **guessing**.

# COMMANDS

## Dictionary Management

**add *dictionary* \[*dict_type*\]**  
Create a new dictionary, optionally with a specific type.

**del *dictionary***  
Delete a dictionary.

**show \[*dictionary*\]**  
Display dictionary information. Without arguments, shows all
dictionaries.

<!-- -->

**show_oid \[**--full**\] *dictionary***  
Show the OID of the dictionary:
**dictionary\|\<realm\>/\<site\>/\<name\>**. With **--full** the full
OID, which names the unit as well:
**dictionary\|\<realm\>/\<site\>/\<unit_path\>/\<name\>**.  
Needs the ACL **view_public:object**.

**show_uuid *dictionary***  
Show the UUID of the dictionary.  
Needs the ACL **view_public:object**.

<!-- -->

**list \[*regex*\]**  
List dictionaries, optionally filtered by regex pattern.

**enable *dictionary***  
Enable a disabled dictionary.

**disable *dictionary***  
Disable a dictionary without deleting it.

**rename *dictionary* *new_name***  
Rename a dictionary.

**move \[**--keep-acls**\] *dictionary* *unit***  
Move dictionary to a different unit.

**touch *dictionary***  
Re-index the object to fix potential index problems.

**auto_disable *dictionary* *time***  
Set auto-disable time. It is either a relative time with a leading
**+**, e.g. **+30D**, or an absolute one, e.g. **"09:53 13.06.2023"**.
The units are **s**, **m**, **h**, **D**, **W**, **M** and **Y**, see
**otpme**(7). A relative time counts from when it is set, and again from
when the dictionary is enabled. **0** removes it. It is refused for an
object the realm or a site comes with, e.g. the admin user; a time set
on one before does nothing.

## Word Management

**word_import *dictionary* *file***  
Import words from a file into the dictionary.

**word_learning *dictionary* *file***  
Analyze words from a file and build a guessing dictionary with character
sequence patterns and their frequencies.

**word_export *dictionary***  
Export all words to stdout.

**clear *dictionary***  
Remove all words from the dictionary.

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

**changelog *dictionary***  
Show the changelog of the dictionary. Needs the ACL **view:changelog**.

**edit_changelog *dictionary* *entry_id* *comment***  
Set the comment of that entry, or replace the one it has. Needs the ACL
**edit:changelog**.

**del_changelog *dictionary* *entry_id***  
Remove the comment of that entry. The entry itself stays, and an entry
without a comment is refused. Needs the ACL **edit:changelog**.

**clear_changelog *dictionary***  
Remove every entry of the changelog.  
This needs more than the ACL **clear:changelog**: the config parameter
**allow_changelog_clearing** has to allow it (see **otpme**(7)). It is
true by default, but where no value is found at all, clearing is
refused. A value set on the token you are signed in with counts first.
Without one, the value of the object counts, read along its cascade.

## Policy Management

A *policy* is the name of a policy, not a path. It is looked for in the
site of the dictionary. Which policies there are, and what each of them
does, is in **otpme-policy**(1).

Attaching and detaching ask before they change anything; the global
option **-f** skips the question.

**add_policy *dictionary* *policy***  
Attach a policy to the dictionary.  
A policy has a list of object types it is for; one that does not name
**dictionary** is refused. So is a second policy of a type that allows
only one per object.  
Needs the ACL **assign:policy**.

**remove_policy *dictionary* *policy***  
Remove a policy from the dictionary.  
Needs the ACL **remove:policy**, and that one verbatim: a plain
**remove** does not cover it. Detaching a policy takes away what it
enforces, so it must not be cheaper than attaching one.

**list_policies \[**--return-type** *TYPE*\] \[**--policy-types** *t1,t2*\] *dictionary***  
List the policies attached to the dictionary, the disabled ones too,
marked **(disabled)**. Use **--return-type** to select the attribute
returned (**name**, **read_oid**, **full_oid**, **uuid**). Use
**--policy-types** to list only policies of the given types; these are
policy types, not policy names.  
Needs the ACL **view:policies**.

## ACL Management

**add_acl *dictionary* *owner_type* *owner* *acl***  
Add an access control entry.

**del_acl *dictionary* *acl***  
Remove an access control entry.

**list_acls *dictionary***  
Display all ACLs for the dictionary.

**enable_acl_inheritance *dictionary***  
Let a move of the dictionary swap its default ACLs: what the old unit
handed down is taken away, and what the new unit hands down is given. It
does not by default; a move then leaves the ACLs of the dictionary as
they are.

Only a move asks this. A new dictionary gets the default ACLs of its
unit, and **add_acl -a** or **-r** on a unit reach it either way. A move
with **--keep-acls** leaves its ACLs alone all the same.

A move by somebody who does not hold **add:acl** and **delete:acl** on
the dictionary leaves its ACLs alone as well, and says so. Otherwise
moving an object into a unit would be a way of handing yourself the
default ACLs of that unit.

Needs the ACL **enable:acl_inheritance**.

**disable_acl_inheritance *dictionary***  
A move leaves the ACLs of the dictionary as they are again.  
Needs the ACL **disable:acl_inheritance**.

## Configuration

**description *dictionary* \[*description*\]**  
Set dictionary description.

**info \[**--language** *LANG*\] *dictionary* \[*info*\]**  
Set free-form info text. If *info* is omitted, the current info text is
opened in the editor specified by the **EDITOR** environment variable.

**dump_info \[**--language** *LANG*\] *dictionary***  
Dump the info text to stdout.

## Import/Export

**export \[**--password** *PASS*\] *dictionary***  
Export dictionary configuration.

# OPTIONS

## Display Options

**-a**  
Show all dictionaries (across all units).

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
Of **list**: match the regex against this attribute instead of the name.

## General Options

**--keep-acls**  
Preserve ACLs when moving dictionary.

**--password *PASS***  
Password for encrypting exports.

Global options are available for all commands. See **otpme**(1) for
details.

# EXAMPLES

## Managing Dictionaries

**otpme-dictionary add english list**  
Create a word list dictionary

**otpme-dictionary add english_guessing guessing**  
Create a guessing dictionary

**otpme-dictionary word_import english /usr/share/dict/words**  
Import words from a file

**otpme-dictionary word_learning english_guessing /usr/share/dict/words**  
Build guessing patterns from a word file

**otpme-dictionary word_export english**  
Export all words to stdout

**otpme-dictionary clear english**  
Remove all words from the dictionary

# AUTH ON ACTION HOOKS

An auth on action policy can ask for a login again before these actions.
See **Auth On Action Policy** in **otpme-policy**(1). A dictionary has
the hooks every object type has, and no others.

# FILES

*/var/lib/otpme/*  
OTPme data directory

# SEE ALSO

**otpme**(7), **otpme-acls**(7), **otpme-policy**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
