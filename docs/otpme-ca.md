# NAME

otpme-ca - manage OTPme certificate authorities

# SYNOPSIS

**otpme-ca** *command* \[*options*\] \[*ca*\]

# DESCRIPTION

**otpme-ca** manages certificate authorities (CAs) in the OTPme system.
CAs issue and manage X.509 certificates for nodes and hosts, maintain
certificate revocation lists (CRLs), and provide the PKI infrastructure
for secure communication between OTPme components.

Each CA generates a self-signed CA certificate with configurable X.509
distinguished name fields. CAs can issue server, client, node, and host
certificates. CRL data is propagated to all nodes in the realm.

# COMMANDS

## CA Management

**add \[*options*\] *ca***  
Create a new CA with a self-signed certificate.

**del *ca***  
Delete a CA.

**show \[*ca*\]**  
Display CA information. Without arguments, shows all CAs.

**list \[*regex*\]**  
List CAs, optionally filtered by regex pattern.

**enable *ca***  
Enable a disabled CA.

**disable *ca***  
Disable a CA without deleting it.

**touch *ca***  
Re-index the object to fix potential index problems.

## Certificate Operations

**dump_cert *ca***  
Export the CA certificate to stdout.

**dump_key \[**-p** *passphrase*\] *ca***  
Export the CA private key to stdout. Use **-p** to encrypt with a
passphrase.

**dump_ca_chain *ca***  
Export the CA certificate chain to stdout.

**create_client_cert \[*X.509* options\] *ca* *cn* *cert_out_file* *key_out_file***  
Create a client certificate signed by the CA and write it to
*cert_out_file*/*key_out_file*. Used for non-OTPme hosts that need to
authenticate against **backupd**; see **BACKUP_CLIENT_CERT** in
**otpme.conf**(5). The X.509 options are the same as for **add**
(**--country**, **--state**, **--locality**, **--organization**,
**--ou**, **--email**, **--valid**, **--key-len**).

## CRL Management

**crl_validity *ca* *days***  
Set CRL validity period in days.

**dump_crl *ca***  
Export the certificate revocation list to stdout.

**update_crl *ca***  
Remove outdated certificates from the CRL.

## Configuration

**config \[**-d**\] \[**-a**\] *ca* *parameter* \[*value*\]**  
Set a configuration parameter. Use **-d** to delete (reset to default)
or **-a** to append the value to a list-typed parameter.

**show_config *ca* \[*parameter*\]**  
Show all configuration parameters.

**get_config *ca* *parameter***  
Show the value of a single configuration parameter.

**description *ca* \[*description*\]**  
Set CA description.

**info \[**--language** *LANG*\] *ca* \[*info*\]**  
Set free-form info text. If *info* is omitted, the current info text is
opened in the editor specified by the **EDITOR** environment variable.

**dump_info \[**--language** *LANG*\] *ca***  
Dump the info text to stdout.

## Object Changelog

**changelog *ca***  
Show the object's changelog (chronological list of changes with author,
timestamp and optional custom text passed via **--changelog**).

**edit_changelog *ca* *changelog_id***  
Open the given changelog entry in the editor named by **EDITOR** to edit
its custom text.

**del_changelog *ca* *changelog_id***  
Remove a single entry from the object's changelog.

**clear_changelog *ca***  
Clear the object's entire changelog.

## Policy Management

**add_policy *ca* *policy***  
Attach a policy to the CA.

**remove_policy *ca* *policy***  
Remove a policy from the CA.

**list_policies \[**--return-type** *TYPE*\] \[**--policy-types** *t1,t2*\] \[*ca*\]**  
List policies attached to the CA. Use **--return-type** to select the
attribute returned (**name**, **read_oid**, **full_oid**, **uuid**) and
**--policy-types** to limit the listing to the given policy types.

## ACL Management

**add_acl *ca* *owner_type* *owner* *acl***  
Add an access control entry.

**del_acl *ca* *acl***  
Remove an access control entry.

**show_acls *ca***  
Display all ACLs for the CA.

**enable_acl_inheritance *ca***  
Enable ACL inheritance from parent objects.

**disable_acl_inheritance *ca***  
Disable ACL inheritance.

## Import/Export

**export \[**--password** *PASS*\] *ca***  
Export CA configuration.

**remove_orphans *ca***  
Remove orphaned object references.

# OPTIONS

## CA Creation Options

**--country *COUNTRY***  
Set X.509 country field.

**--state *STATE***  
Set X.509 state field.

**--locality *LOCALITY***  
Set X.509 locality field.

**--organization *ORG***  
Set X.509 organization field.

**--ou *OU***  
Set X.509 organizational unit field.

**--email *EMAIL***  
Set X.509 email field.

**--valid *DAYS***  
CA certificate validity in days.

**--key-len *BITS***  
Key length for CA certificate in bits.

## Display Options

**-a**  
Show all CAs (across all units).

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

## Creating a CA

**otpme-ca add myca**  
Create a new CA with default settings

**otpme-ca add --key-len 4096 --valid 3650 --country DE --organization Example Corp myca**  
Create CA with specific key length, validity, and X.509 fields

## Certificate and CRL Operations

**otpme-ca dump_cert myca**  
Export CA certificate

**otpme-ca dump_key -p mysecret myca**  
Export CA private key encrypted with passphrase

**otpme-ca dump_ca_chain myca**  
Export certificate chain

**otpme-ca crl_validity myca 365**  
Set CRL validity to 365 days

**otpme-ca dump_crl myca**  
Export CRL

**otpme-ca update_crl myca**  
Remove expired certificates from CRL

# FILES

*/var/lib/otpme/*  
OTPme data directory

# SEE ALSO

**otpme**(7), **otpme-site**(1), **otpme-node**(1), **otpme-host**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
