# OTPME-DICTIONARY(1)

## NAME

otpme-dictionary - manage OTPme dictionaries

## SYNOPSIS

**otpme-dictionary**
*command*
[*options*] [*dictionary*]

## DESCRIPTION

**otpme-dictionary**
manages dictionaries in the OTPme system. Dictionaries are word lists used by password policies for password strength checking and passphrase generation. Supported dictionary types are
list,
sorted-list,
and
guessing.

## COMMANDS

### Dictionary Management

**add *dictionary* [*dict_type*]**
:   Create a new dictionary, optionally with a specific type.

**del *dictionary***
:   Delete a dictionary.

**show [*dictionary*]**
:   Display dictionary information. Without arguments, shows all dictionaries.

**list [*regex*]**
:   List dictionaries, optionally filtered by regex pattern.

**enable *dictionary***
:   Enable a disabled dictionary.

**disable *dictionary***
:   Disable a dictionary without deleting it.

**rename *dictionary* *new_name***
:   Rename a dictionary.

**move [**--keep-acls**] *dictionary* *unit***
:   Move dictionary to a different unit.

**touch *dictionary***
:   Re-index the object to fix potential index problems.

### Word Management

**word_import *dictionary* *file***
:   Import words from a file into the dictionary.

**word_learning *dictionary* *file***
:   Analyze words from a file and build a guessing dictionary with character sequence patterns and their frequencies.

**word_export *dictionary***
:   Export all words to stdout.

**clear *dictionary***
:   Remove all words from the dictionary.

### Policy Management

**add_policy *dictionary* *policy***
:   Attach a policy to the dictionary.

**remove_policy *dictionary* *policy***
:   Remove a policy from the dictionary.

**list_policies *dictionary***
:   List policies attached to the dictionary.

### ACL Management

**add_acl *dictionary* *owner_type* *owner* *acl***
:   Add an access control entry.

**del_acl *dictionary* *acl***
:   Remove an access control entry.

**show_acls *dictionary***
:   Display all ACLs for the dictionary.

**enable_acl_inheritance *dictionary***
:   Enable ACL inheritance from parent objects.

**disable_acl_inheritance *dictionary***
:   Disable ACL inheritance.

### Configuration

**description *dictionary* [*description*]**
:   Set dictionary description.

### Import/Export

**export [**--password** *PASS*] *dictionary***
:   Export dictionary configuration.

## OPTIONS

### Display Options

**-a**
:   Show all dictionaries (across all units).

**-z *SIZE***
:   Limit output size.

**--fields *FIELD1,FIELD2***
:   Display only specified fields.

**--policy-limit *N***
:   Limit number of policies shown.

**--sort-by *FIELD***
:   Sort output by field.

**--reverse**
:   Reverse sort order.

**--raw**
:   Output without headers/borders.

**--csv**
:   Output as CSV.

**--csv-sep *SEP***
:   CSV separator character.

**--attribute *ATTR***
:   Display specific attribute in list command.

### General Options

**--keep-acls**
:   Preserve ACLs when moving dictionary.

**--password *PASS***
:   Password for encrypting exports.

Global options are available for all commands. See
[otpme(1)](otpme.md)
for details.

## CONFIG PARAMETERS

Configuration parameters can be set with the **config** command and displayed with **show_config**.
For a complete description of all available parameters and their applicable object types, see
[otpme(7)](otpme.7.md).

## EXAMPLES

### Managing Dictionaries

**otpme-dictionary add english list**
:   Create a word list dictionary

**otpme-dictionary add english_guessing guessing**
:   Create a guessing dictionary

**otpme-dictionary word_import english /usr/share/dict/words**
:   Import words from a file

**otpme-dictionary word_learning english_guessing /usr/share/dict/words**
:   Build guessing patterns from a word file

**otpme-dictionary word_export english**
:   Export all words to stdout

**otpme-dictionary clear english**
:   Remove all words from the dictionary

## FILES

*/var/lib/otpme/*
:   OTPme data directory

## SEE ALSO

[otpme(7)](otpme.7.md),
[otpme-policy(1)](otpme-policy.md)

## AUTHOR

the2nd <the2nd@otpme.org>

## NOTE

This manual page was created with AI assistance.

## COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
