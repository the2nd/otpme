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
refused. OTPme asks the token you are signed in with first, then the
object.

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
List the policies attached to the dictionary. Use **--return-type** to
select the attribute returned (**name**, **read_oid**, **full_oid**,
**uuid**). Use **--policy-types** to list only policies of the given
types; these are policy types, not policy names.  
Needs the ACL **view:policies**.

## ACL Management

**add_acl *dictionary* *owner_type* *owner* *acl***  
Add an access control entry.

**del_acl *dictionary* *acl***  
Remove an access control entry.

**list_acls *dictionary***  
Display all ACLs for the dictionary.

**enable_acl_inheritance *dictionary***  
Enable ACL inheritance from parent objects.

**disable_acl_inheritance *dictionary***  
Disable ACL inheritance.

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
Display specific attribute in list command.

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

# FILES

*/var/lib/otpme/*  
OTPme data directory

# SEE ALSO

**otpme**(7), **otpme-policy**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
