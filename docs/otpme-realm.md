# NAME

otpme-realm - manage OTPme realms

# SYNOPSIS

**otpme-realm** *command* \[*options*\] \[*realm*\]

# DESCRIPTION

**otpme-realm** manages realms in the OTPme system. A realm is the
top-level organizational unit that contains all objects (users, tokens,
hosts, nodes, groups, etc.). The realm is initialized with a CA
hierarchy and a master site.

# COMMANDS

## Realm Initialization

**init \[*options*\] *realm* *site* *fqdn* \[*address*\]**  
Initialize a new realm. Creates the realm with a master site, CA
hierarchy, and initial node. This is the first command run when setting
up a new OTPme installation.

## Display

**show \[*realm*\]**  
Display realm information. Without arguments, shows all realms.

**list \[*regex*\]**  
List realms, optionally filtered by regex pattern.

## Authentication and Synchronization

**enable_auth *realm***  
Enable authentication with a trusted realm.

**disable_auth *realm***  
Disable authentication with a trusted realm.

**enable_sync *realm***  
Enable synchronization with a trusted realm.

**disable_sync *realm***  
Disable synchronization with a trusted realm.

## CA Data

**dump_ca_data *realm***  
Dump realm CA data (certificates and CRLs) to stdout.

**update_ca_data *realm***  
Update realm CA data (certificates and CRLs).

## Policy Management

A realm takes one policy and no other: the auth-on-action policy that
realm init attaches.

A policy object lives in a site, a realm does not. A realm that carried
a policy would carry the one of whichever site answered first, and the
admins of that site would then decide what the whole realm enforces.
Auth on action is the exception because the realm has hooks of its own,
and somebody has to be asked before they run.

Everything else is said on the site, on the unit, or on the object.
Nothing ever looked for another policy here: policies are read from the
object itself, and the search does not walk up to the realm.

Attaching and detaching ask before they change anything; the global
option **-f** skips the question.

**add_policy *realm* *policy***  
Attach the auth-on-action policy to the realm. Any other policy is
refused, and so is a second one of this type.  
*policy* is the name of a policy, not a path.  
Needs the ACL **assign:policy**.

**remove_policy *realm* *policy***  
Remove a policy from the realm.  
Needs the ACL **remove:policy**, and that one verbatim: a plain
**remove** does not cover it. Detaching a policy takes away what it
enforces, so it must not be cheaper than attaching one.

**list_policies \[**--return-type** *TYPE*\] \[**--policy-types** *t1,t2*\] *realm***  
List the policies attached to the realm. Use **--return-type** to select
the attribute returned (**name**, **read_oid**, **full_oid**, **uuid**).
Use **--policy-types** to list only policies of the given types; these
are policy types, not policy names.  
Needs the ACL **view:policies**.

## ACL Management

**add_acl *realm* *owner_type* *owner* *acl***  
Add an access control entry.

**del_acl *realm* *acl***  
Remove an access control entry.

**list_acls *realm***  
Display all ACLs for the realm.

## Extension and Attribute Management

**add_extension *realm* *extension***  
Add an extension to the realm.

**remove_extension *realm* *extension***  
Remove an extension from the realm.

**add_attribute *realm* *attribute*=*value***  
Add an LDAP attribute to the realm.

**modify_attribute *realm* *attribute* *old_value* *new_value***  
Modify an LDAP attribute of the realm.

**del_attribute *realm* *attribute*=*value***  
Remove an LDAP attribute from the realm.

**add_object_class *realm* *class***  
Add an LDAP object class to the realm.

**del_object_class *realm* *class***  
Remove an LDAP object class from the realm.

**show_ldif \[**-a** *attributes*\] *realm***  
Show LDIF representation of the realm. Use **-a** to show only specific
attributes.

## Configuration and Attributes

**description *realm* \[*description*\]**  
Set realm description.

**info \[**--language** *LANG*\] *realm* \[*info*\]**  
Set free-form info text. If *info* is omitted, the current info text is
opened in the editor specified by the **EDITOR** environment variable.

**dump_info \[**--language** *LANG*\] *realm***  
Dump the info text to stdout.

**touch *realm***  
Re-index the object to fix potential index problems.

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

**changelog *realm***  
Show the changelog of the realm. Needs the ACL **view:changelog**.

**edit_changelog *realm* *entry_id* *comment***  
Set the comment of that entry, or replace the one it has. Needs the ACL
**edit:changelog**.

**del_changelog *realm* *entry_id***  
Remove the comment of that entry. The entry itself stays, and an entry
without a comment is refused. Needs the ACL **edit:changelog**.

**clear_changelog *realm***  
Remove every entry of the changelog.  
This needs more than the ACL **clear:changelog**: the config parameter
**allow_changelog_clearing** has to allow it (see **otpme**(7)). It is
true by default, but where no value is found at all, clearing is
refused. OTPme asks the token you are signed in with first, then the
object.

## Import/Export

**export \[**--password** *PASS*\] *realm***  
Export realm configuration.

**remove_orphans *realm***  
Remove orphaned object references.

# INIT OPTIONS

These options are used with the **init** command:

## CA Certificate Options

**--ca-valid *DAYS***  
CA certificate validity in days.

**--ca-key-len *BITS***  
Key length for CA certificates in bits.

**--country *COUNTRY***  
Set CA certificate country field.

**--state *STATE***  
Set CA certificate state field.

**--locality *LOCALITY***  
Set CA certificate locality field.

**--organization *ORG***  
Set CA certificate organization field.

**--ou *OU***  
Set CA certificate organizational unit field.

**--email *EMAIL***  
Set CA certificate email field.

## Site and Node Certificate Options

**--site-valid *DAYS***  
Master site certificate validity in days.

**--site-key-len *BITS***  
Key length for master site certificate in bits.

**--node-valid *DAYS***  
Master node certificate validity in days.

**--node-key-len *BITS***  
Key length for master node certificate in bits.

## Dictionary and ID Range Options

**--no-dicts**  
Do not add any word dictionaries for password strength checking.

**--dicts *dict1,dict2***  
Add the given word dictionaries for password strength checking.

**--id-ranges *range1,range2***  
ID ranges to add during initialization.

**--no-index-indices**  
Skip creation of index-DB indices during **init**. Use only for special
setups (e.g. very small test realms) where the extra indices are not
wanted; the default is to create them.

# OPTIONS

## Display Options

**-a**  
Show all realms.

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

**--password *PASS***  
Password for encrypting exports.

Global options are available for all commands. See **otpme**(1) for
details.

# EXAMPLES

## Initializing a Realm

**otpme-realm init myrealm master node1.example.com 10.0.0.1**  
Initialize a new realm with master site and node

**otpme-realm init --ca-key-len 4096 myrealm master node1.example.com**  
Initialize with 4096-bit CA keys

## CA Data

**otpme-realm dump_ca_data myrealm**  
Export CA certificates and CRLs

# FILES

*/var/lib/otpme/*  
OTPme data directory

# SEE ALSO

**otpme**(1), **otpme**(7), **otpme-acls**(7), **otpme-site**(1),
**otpme-ca**(1), **otpme-node**(1), **otpme-policy**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
