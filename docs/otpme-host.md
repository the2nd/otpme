# OTPME-HOST(1)

## NAME

otpme-host - manage OTPme hosts

## SYNOPSIS

**otpme-host**
*command*
[*options*] [*host*]

## DESCRIPTION

**otpme-host**
manages host objects in the OTPme system. Hosts are client machines (e.g. notebooks, workstations) that are joined to the OTPme realm and on which users log in. Hosts have certificates, can be configured with tokens, roles, dynamic groups, and sync settings.

## COMMANDS

### Host Management

**add *host***
:   Create a new host.

**del *host***
:   Delete a host.

**show [*host*]**
:   Display host information. Without arguments, shows all hosts.

**list [*regex*]**
:   List hosts, optionally filtered by regex pattern.

**enable *host***
:   Enable a disabled host.

**disable *host***
:   Disable a host without deleting it.

**move [**--keep-acls**] *host* *unit***
:   Move host to a different unit.

**touch *host***
:   Re-index the object to fix potential index problems.

### Token and Role Assignment

**add_token [**-i** *interfaces*] [**--no-auto-sign**] [**--sign** **--tags** *tag1,tag2*] *host* *token_path***
:   Add a token to the host. Use **-i** to limit login to specific interfaces (e.g. tty, gui, ssh).

**remove_token [**--keep-sign**] *host* *token_path***
:   Remove a token from the host.

**list_tokens *host***
:   List tokens assigned to the host.

**add_role *host* *role***
:   Add a role to the host.

**remove_role *host* *role***
:   Remove a role from the host.

**list_roles *host***
:   List roles assigned to the host.

### Login Control

**limit_logins *host***
:   Limit logins to tokens and roles explicitly assigned to this host.

**unlimit_logins *host***
:   Allow logins from all authorized tokens.

### User and Group Listing

**list_users *host***
:   List users on the host.

**list_sync_users *host***
:   List sync users on the host.

**list_sync_groups *host***
:   List sync groups on the host.

**list_dynamic_groups *host***
:   List dynamic groups of the host.

### Dynamic Groups

Dynamic groups are local Linux groups (e.g. plugdev) that exist on hosts and nodes. Users are automatically added to these groups when they log in via the OTPme PAM module. This is most commonly used on hosts where users log in interactively.

**add_dynamic_group *host* *group***
:   Add a dynamic group to the host.

**remove_dynamic_group *host* *group***
:   Remove a dynamic group from the host.

### Sync Configuration

**add_sync_user *host* *user***
:   Add a sync user to the host.

**remove_sync_user *host* *user***
:   Remove a sync user from the host.

**add_sync_group *host* *group***
:   Add a sync group to the host.

**remove_sync_group *host* *group***
:   Remove a sync group from the host.

**enable_sync_groups *host***
:   Enable sync groups.

**disable_sync_groups *host***
:   Disable sync groups.

**enable_sync_by_login_token *host***
:   Enable sync by login token.

**disable_sync_by_login_token *host***
:   Disable sync by login token.

### Realm Join/Leave

**enable_jotp *host***
:   Enable realm join via JOTP.

**disable_jotp *host***
:   Disable realm join via JOTP.

**enable_lotp *host***
:   Enable realm leaving via LOTP.

**disable_lotp *host***
:   Disable realm leaving via LOTP.

**enable_jotp_rejoin *host***
:   Enable printing of rejoin JOTP on realm leave.

**disable_jotp_rejoin *host***
:   Disable printing of rejoin JOTP on realm leave.

### Certificate Operations

**dump_cert *host***
:   Export the host certificate to stdout.

**dump_ca_chain *host***
:   Export the CA certificate chain of the host cert to stdout.

**renew_cert *host***
:   Renew the host certificate.

**public_key *host* [*public_key*]**
:   Set or display the host's public key.

### SSH

**get_ssh_authorized_keys *host* [*user*]**
:   Get SSH authorized keys for the host, optionally for a specific user.

### Policy Management

**add_policy *host* *policy***
:   Attach a policy to the host.

**remove_policy *host* *policy***
:   Remove a policy from the host.

**list_policies *host***
:   List policies attached to the host.

### ACL Management

**add_acl *host* *owner_type* *owner* *acl***
:   Add an access control entry.

**del_acl *host* *acl***
:   Remove an access control entry.

**show_acls *host***
:   Display all ACLs for the host.

**enable_acl_inheritance *host***
:   Enable ACL inheritance from parent objects.

**disable_acl_inheritance *host***
:   Disable ACL inheritance.

### Configuration and Attributes

**config [**-d**] *host* *parameter* [*value*]**
:   Set or display a configuration parameter. Use **-d** to delete (reset to default).

**show_config *host* [*parameter*]**
:   Show all configuration parameters.

**description *host* [*description*]**
:   Set host description.

### Import/Export

**export [**--password** *PASS*] *host***
:   Export host configuration.

**remove_orphans *host***
:   Remove orphaned object references.

## OPTIONS

### Display Options

**-a**
:   Show all hosts (across all units).

**-t**
:   Show host templates.

**-z *SIZE***
:   Limit output size.

**--fields *FIELD1,FIELD2***
:   Display only specified fields.

**--role-limit *N***
:   Limit number of roles shown.

**--token-limit *N***
:   Limit number of tokens shown.

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

### Token Options

**-i *interfaces***
:   Limit login to given interfaces (e.g. tty, gui, ssh).

**--sign**
:   Sign the object with default tags.

**--tags *tag1,tag2***
:   Add tags to signature.

**--no-auto-sign**
:   Do not automatically sign when adding a token.

**--keep-sign**
:   Do not remove any signature when removing a token.

### General Options

**--keep-acls**
:   Preserve ACLs when moving host.

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

### Managing Hosts

**otpme-host add notebook1**
:   Create a new host

**otpme-host enable_jotp notebook1**
:   Enable realm join via JOTP

### Token Assignment

**otpme-host add_token notebook1 alice/totp**
:   Allow alice's TOTP token to login on host

**otpme-host add_token -i ssh notebook1 bob/ssh_key**
:   Allow bob's SSH key only for SSH interface

**otpme-host limit_logins notebook1**
:   Limit logins to explicitly assigned tokens

### Certificate Operations

**otpme-host dump_cert notebook1**
:   Export host certificate

**otpme-host renew_cert notebook1**
:   Renew the host certificate

### Sync Configuration

**otpme-host add_sync_user notebook1 alice**
:   Add sync user

**otpme-host add_sync_group notebook1 developers**
:   Add sync group

## FILES

*/var/lib/otpme/*
:   OTPme data directory

## SEE ALSO

[otpme(1)](otpme.md),
[otpme(7)](otpme.7.md),
[otpme-node(1)](otpme-node.md),
[otpme-token(1)](otpme-token.md),
[otpme-role(1)](otpme-role.md),
[otpme-ca(1)](otpme-ca.md)

## AUTHOR

the2nd <the2nd@otpme.org>

## NOTE

This manual page was created with AI assistance.

## COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
