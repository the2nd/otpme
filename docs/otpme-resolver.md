# OTPME-RESOLVER(1)

## NAME

otpme-resolver - manage OTPme resolvers for importing objects from external directories

## SYNOPSIS

**otpme-resolver**
[**--type** *resolver_type*]
*command*
[*options*] [*resolver*]

## DESCRIPTION

**otpme-resolver**
manages resolvers in the OTPme system. Resolvers synchronize objects (users, groups) from external directory services into OTPme. Currently the supported resolver type is LDAP, which connects to LDAP directories (e.g. Active Directory, OpenLDAP) and imports user and group objects.

Resolvers can run periodically at a configured sync interval, and can optionally delete OTPme objects that no longer exist in the external directory.

## COMMANDS

### Resolver Management

**add *resolver***
:   Create a new resolver. Requires **--type** before the command.

**del *resolver***
:   Delete a resolver.

**show [*resolver*]**
:   Display resolver information. Without arguments, shows all resolvers.

**list [*regex*]**
:   List resolvers, optionally filtered by regex pattern.

**enable *resolver***
:   Enable a disabled resolver.

**disable *resolver***
:   Disable a resolver without deleting it.

**rename *resolver* *new_name***
:   Rename a resolver.

**unit *resolver* *unit***
:   Move resolver to a different organizational unit.

### Resolver Operations

**run [**--object-types** *types*] *resolver***
:   Run the resolver to synchronize objects. Use **--object-types** to limit to specific types (e.g. user,group).

**test [**--object-types** *types*] *resolver***
:   Test the resolver without making changes.

**get_objects [**--object-types** *types*] *resolver***
:   Get objects from the resolver source.

**delete_objects [**--object-types** *types*] *resolver***
:   Delete objects imported by the resolver.

### Sync Configuration

**sync_interval *resolver* *interval***
:   Set the automatic sync interval for the resolver.

**key_attribute *resolver* *object_type* *attribute***
:   Set the key attribute used to match objects during sync (e.g. entryUUID).

**enable_sync_units *resolver***
:   Enable synchronization of organizational units.

**disable_sync_units *resolver***
:   Disable synchronization of organizational units.

**enable_deletions *resolver***
:   Enable deletion of OTPme objects that no longer exist in the external directory.

**disable_deletions *resolver***
:   Disable deletion of missing objects.

### LDAP Configuration

These commands are specific to LDAP resolvers:

**ldap_base *resolver* *base_dn***
:   Set the LDAP search base DN (e.g. dc=example,dc=com).

**login_dn *resolver* *dn***
:   Set the DN used to bind to the LDAP server.

**login_password *resolver* [*password*]**
:   Set the password for LDAP bind. If omitted, prompts interactively.

**add_server *resolver* *server_uri***
:   Add an LDAP server URI (e.g. ldaps://ldap.example.com, ldaps://ldap2.example.com:389).

**del_server *resolver* *server_uri***
:   Remove an LDAP server URI.

**add_ldap_filter *resolver* *object_type* *filter***
:   Add an LDAP search filter for a given object type (e.g. user, group).

**del_ldap_filter *resolver* *object_type* *filter***
:   Remove an LDAP search filter.

**add_ldap_attribute *resolver* *object_type* *src_attr* [*dst_attr*]**
:   Add an LDAP attribute mapping for an object type. Maps a source LDAP attribute to an OTPme attribute. If *dst_attr* is omitted, the same attribute name is used.

**del_ldap_attribute *resolver* *object_type* *attribute***
:   Remove an LDAP attribute mapping.

### Policy Management

**add_policy *resolver* *policy***
:   Attach a policy to the resolver.

**remove_policy *resolver* *policy***
:   Remove a policy from the resolver.

**list_policies *resolver***
:   List policies attached to the resolver.

### ACL Management

**add_acl *resolver* *owner_type* *owner* *acl***
:   Add an access control entry.

**del_acl *resolver* *acl***
:   Remove an access control entry.

**show_acls *resolver***
:   Display all ACLs for the resolver.

**enable_acl_inheritance *resolver***
:   Enable ACL inheritance from parent objects.

**disable_acl_inheritance *resolver***
:   Disable ACL inheritance.

### Configuration and Attributes

**config [**-d**] *resolver* *parameter* [*value*]**
:   Set or display a configuration parameter. Use **-d** to delete (reset to default).

**description *resolver* [*description*]**
:   Set resolver description.

### Import/Export

**export *resolver***
:   Export resolver configuration to stdout.

## OPTIONS

**--type *TYPE***
:   Specify the resolver type. Required for the **add** command and for all type-specific commands. Must be placed before the command.

**--object-types *type1,type2***
:   Limit operations to specific object types (e.g. user,group).

### Display Options

**-a**
:   Show all resolvers.

**-z *SIZE***
:   Limit output size.

**--fields *FIELD1,FIELD2***
:   Display only specified fields.

**--policy-limit *N***
:   Limit number of policies shown.

Global options are available for all commands. See
[otpme(1)](otpme.md)
for details.

## CONFIG PARAMETERS

Configuration parameters can be set with the **config** command and displayed with **show_config**.
For a complete description of all available parameters and their applicable object types, see
[otpme(7)](otpme.7.md).

## EXAMPLES

### Setting Up an LDAP Resolver

**otpme-resolver --type ldap add ad_resolver**
:   Create an LDAP resolver

**otpme-resolver add_server ad_resolver ldaps://ad.example.com**
:   Add LDAP server

**otpme-resolver ldap_base ad_resolver dc=example,dc=com**
:   Set search base

**otpme-resolver login_dn ad_resolver cn=readonly,dc=example,dc=com**
:   Set bind DN

**otpme-resolver login_password ad_resolver**
:   Set bind password (prompts interactively)

### Configuring Sync

**otpme-resolver key_attribute ad_resolver user entryUUID**
:   Set key attribute for user matching

**otpme-resolver add_ldap_filter ad_resolver user (objectClass=inetOrgPerson)**
:   Add LDAP search filter for users

**otpme-resolver add_ldap_attribute ad_resolver user cn**
:   Map LDAP attribute cn for users

**otpme-resolver sync_interval ad_resolver 3600**
:   Set sync interval to 1 hour

### Running the Resolver

**otpme-resolver test ad_resolver**
:   Test resolver configuration

**otpme-resolver run ad_resolver**
:   Run the resolver to sync objects

**otpme-resolver run --object-types user ad_resolver**
:   Sync only users

## FILES

*/var/lib/otpme/*
:   OTPme data directory

## SEE ALSO

[otpme(1)](otpme.md),
[otpme(7)](otpme.7.md),
[otpme-user(1)](otpme-user.md),
[otpme-group(1)](otpme-group.md),
[otpme-policy(1)](otpme-policy.md)

## AUTHOR

the2nd <the2nd@otpme.org>

## NOTE

This manual page was created with AI assistance.

## COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
