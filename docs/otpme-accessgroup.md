# OTPME-ACCESSGROUP(1)

## NAME

otpme-accessgroup - manage OTPme access groups for resource authorization

## SYNOPSIS

**otpme-accessgroup**
*command*
[*options*] [*accessgroup*]

## DESCRIPTION

**otpme-accessgroup**
manages access groups in the OTPme system. Access groups control which tokens and roles are authorized to access specific services. They provide centralized access control, session management, timeout configuration, and failure handling.

Access groups are assigned to clients (see
otpme-client (1))
to control who can authenticate. They support hierarchical structures with parent and child groups. For a conceptual overview, see
[otpme(7)](otpme.7.md).

## COMMANDS

### Access Group Management

**add *accessgroup***
:   Create a new access group.

**del *accessgroup***
:   Delete an access group.

**show [*accessgroup*]**
:   Display access group information.

**list [*regex*]**
:   List access groups, optionally filtered by regex pattern.

**enable *accessgroup***
:   Enable a disabled access group.

**disable *accessgroup***
:   Disable an access group without deleting it.

**rename *accessgroup* *new_name***
:   Rename an access group.

**move [**--keep-acls**] *accessgroup* *unit***
:   Move access group to a different unit.

**touch *accessgroup***
:   Re-index the access group to fix potential index problems.

### Token and Role Assignment

**add_token *accessgroup* *token_path***
:   Add a token to the access group. Tokens in the group are authorized to access resources using this group.

**remove_token *accessgroup* *token_path***
:   Remove a token from the access group.

**list_tokens *accessgroup***
:   List tokens assigned to the access group.

**add_role *accessgroup* *role***
:   Add a role to the access group. All tokens with this role are authorized.

**remove_role *accessgroup* *role***
:   Remove a role from the access group.

**list_roles *accessgroup***
:   List roles assigned to the access group.

### Session Management

**enable_sessions *accessgroup***
:   Enable session management for this access group.

**disable_sessions *accessgroup***
:   Disable session management.

**enable_timeout_pass_on *accessgroup***
:   Pass timeout values to child sessions.

**disable_timeout_pass_on *accessgroup***
:   Do not pass timeout values to child sessions.

### Timeout Configuration

**timeout *accessgroup* [*time*]**
:   Set session timeout (e.g., 30m, 2h, 1D, 1W). Default: 1800s (30 minutes).

**unused_timeout *accessgroup* [*time*]**
:   Set timeout for unused sessions. Default: 300s (5 minutes).

**relogin_timeout *accessgroup* [*time*]**
:   Set minimum time before allowing re-login. Default: 0 (immediate).

**max_sessions *accessgroup* [*count*]**
:   Set maximum concurrent sessions (0 = unlimited). Default: 0.

### Failure Handling

**max_fail *accessgroup* [*count*]**
:   Set maximum failed login attempts before locking. Default: 5.

**max_fail_reset *accessgroup* [*time*]**
:   Set time after which failed login counter resets (e.g., 5m, 1h). Default: 0 (no reset).

### Hierarchical Groups

**add_child_group *accessgroup* *child_group***
:   Add a child access group. Tokens assigned to a parent group are also accepted when authenticating to the child group.

**remove_child_group *accessgroup* *child_group***
:   Remove a child access group.

**add_child_session *accessgroup* *session_group***
:   Add a child session group. When a session is created at this access group, child sessions are automatically created for all child session groups.

**remove_child_session *accessgroup* *session_group***
:   Remove a child session group.

### Policy Management

**add_policy *accessgroup* *policy***
:   Attach a policy to the access group.

**remove_policy *accessgroup* *policy***
:   Remove a policy from the access group.

**list_policies *accessgroup***
:   List policies attached to the access group.

### ACL Management

**add_acl *accessgroup* *owner_type* *owner* *acl***
:   Add an access control entry.

**del_acl *accessgroup* *acl***
:   Remove an access control entry.

**show_acls *accessgroup***
:   Display all ACLs for the access group.

**enable_acl_inheritance *accessgroup***
:   Enable ACL inheritance from parent objects.

**disable_acl_inheritance *accessgroup***
:   Disable ACL inheritance.

### Configuration and Attributes

**config [**-d**] *accessgroup* *parameter* [*value*]**
:   Set or display a configuration parameter. Use **-d** to delete (reset to default).

**show_config *accessgroup* [*parameter*]**
:   Show all configuration parameters.

**description *accessgroup* [*description*]**
:   Set access group description.

**add_extension *accessgroup* *extension***
:   Add an extension to the access group.

**remove_extension *accessgroup* *extension***
:   Remove an extension.

**add_attribute *accessgroup* *attribute*=*value***
:   Add an LDAP attribute.

**del_attribute *accessgroup* *attribute*=*value***
:   Remove an LDAP attribute.

**add_object_class *accessgroup* *class***
:   Add an LDAP object class.

**del_object_class *accessgroup* *class***
:   Remove an LDAP object class.

### Import/Export

**export [**--password** *PASS*] *accessgroup***
:   Export access group configuration.

**remove_orphans *accessgroup***
:   Remove orphaned object references.

## OPTIONS

### Display Options

**-a**
:   Show all access groups (across all units).

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
:   Preserve ACLs when moving access group.

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

### Creating and Configuring Access Groups

**otpme-accessgroup add vpn**
:   Create access group for VPN access

**otpme-accessgroup add wlan_building1**
:   Create access group for building 1 WLAN

**otpme-accessgroup description vpn "VPN Access Group"**
:   Set description

### Adding Tokens and Roles

**otpme-accessgroup add_token vpn alice/totp**
:   Allow alice's TOTP token to access VPN

**otpme-accessgroup add_token -i ssh vpn bob/ssh_key**
:   Allow bob's SSH key only for SSH interface

**otpme-accessgroup add_role vpn VPN_USER**
:   Allow all tokens with VPN_USER role

**otpme-accessgroup list_tokens vpn**
:   Show all authorized tokens

### Configuring Sessions

**otpme-accessgroup enable_sessions vpn**
:   Enable session management

**otpme-accessgroup timeout vpn 8h**
:   Set 8-hour session timeout

**otpme-accessgroup unused_timeout vpn 30m**
:   Set 30-minute unused timeout

**otpme-accessgroup max_sessions vpn 3**
:   Allow maximum 3 concurrent sessions

**otpme-accessgroup relogin_timeout vpn 5m**
:   Require 5-minute wait before re-login

### Configuring Failure Handling

**otpme-accessgroup max_fail vpn 3**
:   Lock after 3 failed attempts

**otpme-accessgroup max_fail_reset vpn 10m**
:   Reset failure counter after 10 minutes

### Hierarchical Configuration

**otpme-accessgroup add wlan**
:   Create parent WLAN group

**otpme-accessgroup add wlan_building1**
:   Create child group for building 1

**otpme-accessgroup add_child_group wlan wlan_building1**
:   Link child to parent

**otpme-accessgroup enable_timeout_pass_on wlan**
:   Pass timeout settings to children

### Assigning to a Client

**otpme-client access_group vpn_gateway vpn**
:   Assign access group to VPN gateway client

## FILES

*/var/lib/otpme/*
:   OTPme data directory

## SEE ALSO

[otpme(7)](otpme.7.md),
[otpme-client(1)](otpme-client.md),
[otpme-host(1)](otpme-host.md),
[otpme-token(1)](otpme-token.md),
[otpme-role(1)](otpme-role.md),
[otpme-policy(1)](otpme-policy.md)

## AUTHOR

the2nd <the2nd@otpme.org>

## NOTE

This manual page was created with AI assistance.

## COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
