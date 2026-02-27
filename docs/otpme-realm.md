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

**add_policy *realm* *policy***  
Attach a policy to the realm.

**remove_policy *realm* *policy***  
Remove a policy from the realm.

**list_policies *realm***  
List policies attached to the realm.

## ACL Management

**add_acl *realm* *owner_type* *owner* *acl***  
Add an access control entry.

**del_acl *realm* *acl***  
Remove an access control entry.

**show_acls *realm***  
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

**config *realm* *parameter* \[*value*\]**  
Set or display a configuration parameter.

**show_config *realm* \[*parameter*\]**  
Show all configuration parameters.

**description *realm* \[*description*\]**  
Set realm description.

**touch *realm***  
Re-index the object to fix potential index problems.

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

# CONFIG PARAMETERS

Configuration parameters can be set with the **config** command and
displayed with **show_config**. For a complete description of all
available parameters and their applicable object types, see
**otpme**(7).

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

**otpme**(1), **otpme**(7), **otpme-site**(1), **otpme-ca**(1),
**otpme-node**(1), **otpme-policy**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
