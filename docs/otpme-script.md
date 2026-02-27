# OTPME-SCRIPT(1)

## NAME

otpme-script - manage OTPme scripts

## SYNOPSIS

**otpme-script**
*command*
[*options*] [*script*]

## DESCRIPTION

**otpme-script**
manages scripts in the OTPme system. Scripts are stored as OTPme objects and can be signed to ensure integrity. They are used for various purposes such as login scripts and key scripts.

## COMMANDS

### Script Management

**add [**-r**] *name* *script***
:   Add a new script. Use **-r** to replace an existing script while keeping its UUID.

**del *script***
:   Delete a script.

**show [*script*]**
:   Display script information.

**list [*regex*]**
:   List scripts, optionally filtered by regex pattern.

**enable *script***
:   Enable a disabled script.

**disable *script***
:   Disable a script without deleting it.

**rename *script* *new_name***
:   Rename a script.

**copy *script* *dst_script***
:   Copy a script and its signatures.

**move [**--keep-acls**] *script* *unit***
:   Move script to a different unit.

**touch *script***
:   Re-index the object to fix potential index problems.

### Script Operations

**dump *script***
:   Dump script contents to stdout.

**edit *script***
:   Edit a script.

**run [**--type** *script_type*] *script***
:   Run a script. Use **--type** to run as a specific script type (e.g. key_script).

### Signature Management

**sign [**--stdin-pass**] [**--tags** *tag1,tag2*] *script***
:   Sign a script. Use **--stdin-pass** to read the RSA private key passphrase from stdin.

**resign [**--stdin-pass**] *script***
:   Re-sign all script signatures.

**verify_sign [**--user** *username*] [**--tags** *tag1,tag2*] *script***
:   Verify script signature(s).

**get_sign [**--user** *username*] [**--tags** *tag1,tag2*] *script***
:   Get script signature(s).

**get_sign_data [**--tags** *tag1,tag2*] *script***
:   Get the data to be signed from a script.

**add_sign [**--tags** *tag1,tag2*] *script* *signature***
:   Add a signature to a script.

**del_sign [**--user** *username*] [**--tags** *tag1,tag2*] *script***
:   Delete a signature from a script.

### Policy Management

**add_policy *script* *policy***
:   Attach a policy to the script.

**remove_policy *script* *policy***
:   Remove a policy from the script.

**list_policies *script***
:   List policies attached to the script.

### ACL Management

**add_acl *script* *owner_type* *owner* *acl***
:   Add an access control entry.

**del_acl *script* *acl***
:   Remove an access control entry.

**show_acls *script***
:   Display all ACLs for the script.

**enable_acl_inheritance *script***
:   Enable ACL inheritance from parent objects.

**disable_acl_inheritance *script***
:   Disable ACL inheritance.

### Configuration

**description *script* [*description*]**
:   Set script description.

### Import/Export

**export [**--password** *PASS*] *script***
:   Export script configuration.

**remove_orphans *script***
:   Remove orphaned object references.

## OPTIONS

### Display Options

**-a**
:   Show all scripts.

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

### General Options

**-r**
:   Replace existing script and keep its UUID.

**--keep-acls**
:   Preserve ACLs when moving script.

**--password *PASS***
:   Password for encrypting exports.

**--stdin-pass**
:   Read RSA private key passphrase from stdin.

**--tags *tag1,tag2***
:   Tags for signatures.

**--user *username***
:   Select signature by username.

Global options are available for all commands. See
[otpme(1)](otpme.md)
for details.

## CONFIG PARAMETERS

Configuration parameters can be set with the **config** command and displayed with **show_config**.
For a complete description of all available parameters and their applicable object types, see
[otpme(7)](otpme.7.md).

## EXAMPLES

**otpme-script add myscript /path/to/script.sh**
:   Add a new script

**otpme-script sign myscript**
:   Sign a script

**otpme-script dump myscript**
:   Show script contents

**otpme-script edit myscript**
:   Edit a script

## FILES

*/var/lib/otpme/*
:   OTPme data directory

## SEE ALSO

[otpme(1)](otpme.md),
[otpme(7)](otpme.7.md),
[otpme-user(1)](otpme-user.md),
[otpme-token(1)](otpme-token.md)

## AUTHOR

the2nd <the2nd@otpme.org>

## NOTE

This manual page was created with AI assistance.

## COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
