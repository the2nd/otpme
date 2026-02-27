# OTPME-SITE(1)

## NAME

otpme-site - manage OTPme sites

## SYNOPSIS

**otpme-site**
*command*
[*options*] [*site*]

## DESCRIPTION

**otpme-site**
manages sites in the OTPme system. A site contains nodes and has its own CA hierarchy. Sites can establish trust relationships with other sites to enable cross-site authentication and synchronization.

## COMMANDS

### Site Management

**add [*options*] *site* *node_name* *site_fqdn* [*site_address*]**
:   Create a new site with a master node.

**del *site***
:   Delete a site.

**show [*site*]**
:   Display site information.

**list [*regex*]**
:   List sites, optionally filtered by regex pattern.

**enable *site***
:   Enable a disabled site.

**disable *site***
:   Disable a site without deleting it.

**touch *site***
:   Re-index the object to fix potential index problems.

### Site Configuration

**address *site* [*ip_address*]**
:   Change site IP address.

**auth_fqdn *site* [*fqdn*]**
:   Change site auth FQDN.

**mgmt_fqdn *site* [*fqdn*]**
:   Change site management FQDN.

**config [**-d**] *site* *parameter* [*value*]**
:   Set or display a configuration parameter. Use **-d** to delete (reset to default).

**show_config *site* [*parameter*]**
:   Show all configuration parameters.

**description *site* [*description*]**
:   Set site description.

### Trust Relationships

**add_trust *site* *trusted_site***
:   Add a trust relationship with another site.

**del_trust *site* *trusted_site***
:   Delete a trust relationship.

### Authentication and Synchronization

**enable_auth *site***
:   Enable authentication with site.

**disable_auth *site***
:   Disable authentication with site.

**enable_sync *site***
:   Enable synchronization with site.

**disable_sync *site***
:   Disable synchronization with site.

### Certificate Management

**dump_cert *site***
:   Dump site certificate to stdout.

**dump_key [**-p** *passphrase*] *site***
:   Dump site private key to stdout. Use **-p** to encrypt with passphrase.

**dump_ca_chain *site***
:   Dump site certificate chain to stdout.

**revoke_cert *site***
:   Revoke site certificate.

**renew_cert *site***
:   Renew site certificate.

### RADIUS Certificate

**radius_cert *site* *cert_file***
:   Change RADIUS certificate.

**radius_key *site* *key_file***
:   Change RADIUS certificate key.

**del_radius_cert *site***
:   Delete RADIUS certificate.

**del_radius_key *site***
:   Delete RADIUS key.

### SSO Configuration

**sso_cert *site* *cert_file***
:   Change SSO certificate.

**sso_key *site* *key_file***
:   Change SSO certificate key.

**del_sso_cert *site***
:   Delete SSO certificate.

**del_sso_key *site***
:   Delete SSO key.

**sso_secret *site* *secret***
:   Change SSO secret.

**sso_csrf_secret *site* *secret***
:   Change SSO CSRF secret.

### Cluster

**cluster_key *site* *cluster_key***
:   Change cluster key.

### FIDO2 CA Certificates

**add_fido2_ca_cert *site* *ca_cert_file***
:   Add a FIDO2 CA certificate.

**del_fido2_ca_cert *site* *subject***
:   Delete a FIDO2 CA certificate by subject.

**list_fido2_ca_certs *site***
:   List FIDO2 CA certificates.

### Policy Management

**add_policy *site* *policy***
:   Attach a policy to the site.

**remove_policy *site* *policy***
:   Remove a policy from the site.

**list_policies *site***
:   List policies attached to the site.

### ACL Management

**add_acl [**-r**] [**-a**] [**--objects** *types*] *site* *owner_type* *owner* *acl***
:   Add an access control entry. Use **-r** for recursive, **-a** to apply default ACLs to existing objects.

**del_acl [**-r**] [**-a**] [**--objects** *types*] *site* *acl***
:   Remove an access control entry.

**show_acls *site***
:   Display all ACLs for the site.

### Extension and Attribute Management

**add_extension *site* *extension***
:   Add an extension to the site.

**remove_extension *site* *extension***
:   Remove an extension from the site.

**add_attribute *site* *attribute*=*value***
:   Add an LDAP attribute to the site.

**modify_attribute *site* *attribute* *old_value* *new_value***
:   Modify an LDAP attribute of the site.

**del_attribute *site* *attribute*=*value***
:   Remove an LDAP attribute from the site.

**add_object_class *site* *class***
:   Add an LDAP object class to the site.

**del_object_class *site* *class***
:   Remove an LDAP object class from the site.

**show_ldif [**-a** *attributes*] *site***
:   Show LDIF representation of the site. Use **-a** to show only specific attributes.

### Import/Export

**export [**--password** *PASS*] *site***
:   Export site configuration.

**remove_orphans [**-r**] *site***
:   Remove orphaned object references. Use **-r** for recursive.

## ADD OPTIONS

These options are used with the **add** command:

### CA Certificate Options

**--ca-valid *DAYS***
:   CA certificate validity in days.

**--ca-key-len *BITS***
:   Key length for CA certificates in bits.

**--country *COUNTRY***
:   Set CA certificate country field.

**--state *STATE***
:   Set CA certificate state field.

**--locality *LOCALITY***
:   Set CA certificate locality field.

**--organization *ORG***
:   Set CA certificate organization field.

**--ou *OU***
:   Set CA certificate organizational unit field.

**--email *EMAIL***
:   Set CA certificate email field.

### Site and Node Certificate Options

**--site-valid *DAYS***
:   Site certificate validity in days.

**--site-key-len *BITS***
:   Key length for site certificate in bits.

**--node-valid *DAYS***
:   Master node certificate validity in days.

**--node-key-len *BITS***
:   Key length for master node certificate in bits.

### Dictionary and ID Range Options

**--no-dicts**
:   Do not add any word dictionaries for password strength checking.

**--dicts *dict1,dict2***
:   Add the given word dictionaries for password strength checking.

**--id-ranges *range1,range2***
:   ID ranges to add.

## OPTIONS

### Display Options

**-a**
:   Show all sites.

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

**--password *PASS***
:   Password for encrypting exports.

**--objects *type1,type2***
:   Limit ACL operations to specific object types.

Global options are available for all commands. See
[otpme(1)](otpme.md)
for details.

## CONFIG PARAMETERS

Configuration parameters can be set with the **config** command and displayed with **show_config**.
For a complete description of all available parameters and their applicable object types, see
[otpme(7)](otpme.7.md).

## EXAMPLES

**otpme-site add mysite node1 site.example.com 10.0.0.1**
:   Create a new site

**otpme-site add_trust mysite othersite**
:   Add trust relationship

**otpme-site dump_cert mysite**
:   Dump site certificate

## FILES

*/var/lib/otpme/*
:   OTPme data directory

## SEE ALSO

[otpme(1)](otpme.md),
[otpme(7)](otpme.7.md),
[otpme-realm(1)](otpme-realm.md),
[otpme-node(1)](otpme-node.md),
[otpme-ca(1)](otpme-ca.md)

## AUTHOR

the2nd <the2nd@otpme.org>

## NOTE

This manual page was created with AI assistance.

## COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
