# NAME

otpme-accessgroup - manage OTPme access groups for resource
authorization

# SYNOPSIS

**otpme-accessgroup** *command* \[*options*\] \[*accessgroup*\]

# DESCRIPTION

**otpme-accessgroup** manages access groups in the OTPme system. Access
groups control which tokens and roles are authorized to access specific
services. They provide centralized access control, session management,
timeout configuration, and failure handling.

Access groups are assigned to clients (see **otpme-client**(1)) to
control who can authenticate. They support hierarchical structures with
parent and child groups. For a conceptual overview, see **otpme**(7).

# COMMANDS

## Access Group Management

**add *accessgroup***  
Create a new access group.

**del *accessgroup***  
Delete an access group.

**show \[*accessgroup*\]**  
Display access group information.

**list \[*regex*\]**  
List access groups, optionally filtered by regex pattern.

**enable *accessgroup***  
Enable a disabled access group.

**disable *accessgroup***  
Disable an access group without deleting it.

**rename *accessgroup* *new_name***  
Rename an access group.

**move \[**--keep-acls**\] *accessgroup* *unit***  
Move access group to a different unit.

**touch *accessgroup***  
Re-index the access group to fix potential index problems.

## Token and Role Assignment

**add_token *accessgroup* *token_path***  
Add a token to the access group. Tokens in the group are authorized to
access resources using this group. With SOTP signing enabled the sign
public key of the tokens user is stored in the access group.

**remove_token *accessgroup* *token_path***  
Remove a token from the access group. The users sign public key is
removed with their last token.

**list_tokens \[**--return-type** *TYPE*\] \[**--token-types** *t1,t2*\] *accessgroup***  
List tokens assigned to the access group. Use **--return-type** to
select the attribute returned (**name**, **read_oid**, **full_oid**,
**uuid**) and **--token-types** to limit the listing to the given token
types.

**add_role *accessgroup* *role***  
Add a role to the access group. All tokens with this role are
authorized. Not supported by access groups with SOTP signing enabled.

**remove_role *accessgroup* *role***  
Remove a role from the access group.

**list_roles *accessgroup***  
List roles assigned to the access group.

## Host Assignment

**add_host *accessgroup* *host***  
Add a host to the access group. This is useful for MAC Authentication
Bypass (MAB) port authentication, where hosts are granted network access
based on their access group membership.

**remove_host *accessgroup* *host***  
Remove a host from the access group.

**list_hosts *accessgroup***  
List hosts assigned to the access group.

## Device Assignment

**add_device *accessgroup* *device***  
Add a device to the access group. This is used for MAC Authentication
Bypass (MAB) port authentication of network devices such as printers.

**remove_device *accessgroup* *device***  
Remove a device from the access group.

**list_devices *accessgroup***  
List devices assigned to the access group.

## VLANs

An access group decides whether a token, host or device gets access at
all. Which network it is put into is decided separately, by a VLAN (see
**otpme-vlan**(1)). Both are answered in the same RADIUS reply, but
nothing ties them together: membership in an access group grants no
VLAN, and a VLAN grants no access.

An access group is not assigned a VLAN and cannot be a member of one. To
give the objects of an access group a VLAN, put them, or a role they are
in, into the VLAN:

> **otpme-vlan add_role *vlan* *role***

## Session Management

**enable_sessions *accessgroup***  
Enable session management for this access group.

**disable_sessions *accessgroup***  
Disable session management.

**enable_timeout_pass_on *accessgroup***  
Pass timeout values to child sessions.

**disable_timeout_pass_on *accessgroup***  
Do not pass timeout values to child sessions.

## SOTP Signing

With SOTP signing enabled a client has to sign the SOTP it authenticates
with using the users sign private key. The access group stores a copy of
the sign public key of every user that has a token assigned, and the
node verifies the signature against that copy. This keeps a user of
another site from authenticating with an SOTP alone: whoever controls
the nodes of that site can produce a valid SOTP and can change the users
public key there, but cannot touch the copy inside the access group.
Only daemons that can handle a signed SOTP enforce this, currently
**otpme-mgmtd**(1).

Signing is required from a user only if the access group holds their
sign public key. A user without a key authenticates as before, which is
what makes it possible to enable signing while the users are still
getting their keys. Forced signing drops that exception: every user has
to sign, so a user without a key can no longer authenticate. Access
groups with forced SOTP signing do not support roles, because a role
would bring in tokens whose users sign public keys are missing.

**enable_sotp_signing *accessgroup***  
Require clients to sign the SOTP they authenticate with. The keys of the
users that have one are copied into the access group, users without a
key are named and do not sign.

**disable_sotp_signing *accessgroup***  
Do no longer require clients to sign their SOTP. The sign public keys
stored in the access group are removed with it, and forced signing is
switched off.

**enable_force_sotp_signing *accessgroup***  
Require every user to sign, not just those whose key the access group
holds. Only possible with SOTP signing enabled, no role assigned to the
access group and a stored key for every user with a token assigned. Note
that a token which is only valid through a parent access group has no
key stored and can no longer authenticate.

**disable_force_sotp_signing *accessgroup***  
Only require the users whose sign public key the access group holds to
sign. SOTP signing stays enabled and the stored keys are kept.

**update_sign_public_keys *accessgroup* \[*username*\]**  
Take over the current sign public keys of the users that have a token
assigned, for all of them or only for *username*. A user who generates a
new key pair loses access until this is run, which is on purpose:
updating the copy automatically would hand the users site the control
over it that the copy is meant to take away. Keys of users without a
token in the access group are removed.

## Timeout Configuration

**timeout *accessgroup* \[*time*\]**  
Set session timeout (e.g., 30m, 2h, 1D, 1W). Default: 1800s (30
minutes).

**unused_timeout *accessgroup* \[*time*\]**  
Set timeout for unused sessions. Default: 300s (5 minutes).

**relogin_timeout *accessgroup* \[*time*\]**  
Set minimum time before allowing re-login. Default: 0 (immediate).

**max_sessions *accessgroup* \[*count*\]**  
Set maximum concurrent sessions (0 = unlimited). Default: 0.

## Failure Handling

**max_fail *accessgroup* \[*count*\]**  
Set maximum failed login attempts before locking. Default: 5.

**max_fail_reset *accessgroup* \[*time*\]**  
Set time after which failed login counter resets (e.g., 5m, 1h).
Default: 0 (no reset).

## Hierarchical Groups

**add_child_group *accessgroup* *child_group***  
Add a child access group. Tokens assigned to a parent group are also
accepted when authenticating to the child group.

**remove_child_group *accessgroup* *child_group***  
Remove a child access group.

**add_child_session *accessgroup* *session_group***  
Add a child session group. When a session is created at this access
group, child sessions are automatically created for all child session
groups.

**remove_child_session *accessgroup* *session_group***  
Remove a child session group.

## Object Changelog

**changelog *accessgroup***  
Show the object's changelog (chronological list of changes with author,
timestamp and optional custom text passed via **--changelog**).

**edit_changelog *accessgroup* *changelog_id***  
Open the given changelog entry in the editor named by **EDITOR** to edit
its custom text.

**del_changelog *accessgroup* *changelog_id***  
Remove a single entry from the object's changelog.

**clear_changelog *accessgroup***  
Clear the object's entire changelog.

## Policy Management

**add_policy *accessgroup* *policy***  
Attach a policy to the access group.

**remove_policy *accessgroup* *policy***  
Remove a policy from the access group.

**list_policies \[**--return-type** *TYPE*\] \[**--policy-types** *t1,t2*\] *accessgroup***  
List policies attached to the access group. Use **--return-type** to
select the attribute returned (**name**, **read_oid**, **full_oid**,
**uuid**) and **--policy-types** to limit the listing to the given
policy types.

## ACL Management

**add_acl *accessgroup* *owner_type* *owner* *acl***  
Add an access control entry.

**del_acl *accessgroup* *acl***  
Remove an access control entry.

**show_acls *accessgroup***  
Display all ACLs for the access group.

**enable_acl_inheritance *accessgroup***  
Enable ACL inheritance from parent objects.

**disable_acl_inheritance *accessgroup***  
Disable ACL inheritance.

## Configuration and Attributes

**config \[**-d**\] \[**-a**\] *accessgroup* *parameter* \[*value*\]**  
Set a configuration parameter. Use **-d** to delete (reset to default)
or **-a** to append the value to a list-typed parameter.

**show_config *accessgroup* \[*parameter*\]**  
Show all configuration parameters.

**get_config *accessgroup* *parameter***  
Show the value of a single configuration parameter.

**description *accessgroup* \[*description*\]**  
Set access group description.

**info \[**--language** *LANG*\] *accessgroup* \[*info*\]**  
Set free-form info text. If *info* is omitted, the current info text is
opened in the editor specified by the **EDITOR** environment variable.

**dump_info \[**--language** *LANG*\] *accessgroup***  
Dump the info text to stdout.

**add_extension *accessgroup* *extension***  
Add an extension to the access group.

**remove_extension *accessgroup* *extension***  
Remove an extension.

**add_attribute *accessgroup* *attribute*=*value***  
Add an LDAP attribute.

**del_attribute *accessgroup* *attribute*=*value***  
Remove an LDAP attribute.

**add_object_class *accessgroup* *class***  
Add an LDAP object class.

**del_object_class *accessgroup* *class***  
Remove an LDAP object class.

## Import/Export

**export \[**--password** *PASS*\] *accessgroup***  
Export access group configuration.

**remove_orphans *accessgroup***  
Remove orphaned object references.

# OPTIONS

## Display Options

**-a**  
Show all access groups (across all units).

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
Preserve ACLs when moving access group.

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

## Creating and Configuring Access Groups

**otpme-accessgroup add vpn**  
Create access group for VPN access

**otpme-accessgroup add wlan_building1**  
Create access group for building 1 WLAN

**otpme-accessgroup description vpn VPN Access Group**  
Set description

## Adding Tokens and Roles

**otpme-accessgroup add_token vpn alice/totp**  
Allow alice's TOTP token to access VPN

**otpme-accessgroup add_token -i ssh vpn bob/ssh_key**  
Allow bob's SSH key only for SSH interface

**otpme-accessgroup add_role vpn VPN_USER**  
Allow all tokens with VPN_USER role

**otpme-accessgroup list_tokens vpn**  
Show all authorized tokens

## Configuring Sessions

**otpme-accessgroup enable_sessions vpn**  
Enable session management

**otpme-accessgroup timeout vpn 8h**  
Set 8-hour session timeout

**otpme-accessgroup unused_timeout vpn 30m**  
Set 30-minute unused timeout

**otpme-accessgroup max_sessions vpn 3**  
Allow maximum 3 concurrent sessions

**otpme-accessgroup relogin_timeout vpn 5m**  
Require 5-minute wait before re-login

## Configuring Failure Handling

**otpme-accessgroup max_fail vpn 3**  
Lock after 3 failed attempts

**otpme-accessgroup max_fail_reset vpn 10m**  
Reset failure counter after 10 minutes

## Hierarchical Configuration

**otpme-accessgroup add wlan**  
Create parent WLAN group

**otpme-accessgroup add wlan_building1**  
Create child group for building 1

**otpme-accessgroup add_child_group wlan wlan_building1**  
Link child to parent

**otpme-accessgroup enable_timeout_pass_on wlan**  
Pass timeout settings to children

## Assigning to a Client

**otpme-client access_group vpn_gateway vpn**  
Assign access group to VPN gateway client

# FILES

*/var/lib/otpme/*  
OTPme data directory

# SEE ALSO

**otpme**(7), **otpme-client**(1), **otpme-host**(1),
**otpme-token**(1), **otpme-role**(1), **otpme-vlan**(1),
**otpme-policy**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
