# NAME

otpme-policy - manage OTPme security and business policies

# SYNOPSIS

**otpme-policy** \[**--type** *policy_type*\] *command* \[*options*\]
\[*policy*\]

# DESCRIPTION

**otpme-policy** manages policies in the OTPme system. Policies are
objects that can be attached to other OTPme objects (users, tokens,
hosts, nodes, groups, units, roles, etc.) and are triggered via hooks
when actions are performed on those objects. Each policy type defines
which hooks it handles (e.g. check_password, check_pin, authenticate)
and which object types it applies to. When an action is performed on an
object, all assigned policies are evaluated through the run_policies()
mechanism.

# POLICY TYPES

OTPme supports the following policy types:

**password**  
Password and PIN complexity requirements. Controls minimum length,
character requirements, and strength checking.

**logintimes**  
Time-based access control. Restricts authentication to specific time
windows.

**autodisable**  
Automatic account or token disabling. Disables objects after a specified
time or after a period of inactivity.

**forcetoken**  
Token enforcement policy. Requires specific token types or pass types
for authentication.

**authonaction**  
Authentication on action. Requires re-authentication before performing
sensitive operations (hooks).

**defaultunits**  
Default organizational units. Specifies default units for creating new
objects of specific types.

**defaultgroups**  
Default group assignments. Automatically adds new users to specified
groups and sets the user's default (primary) group.

**defaultroles**  
Default role assignments. Automatically adds a new user's default token
to the specified roles.

**defaultpolicies**  
Default policy assignments. Automatically applies policies to new
objects of a given type.

**idrange**  
ID range management. Controls uidNumber and gidNumber ranges for users
and groups.

**tokenacls**  
Token ACL policy. Assigns ACLs to newly created tokens and to the
user/token that created them.

**objecttemplates**  
Object templates. Provides templates for creating new objects with
predefined configurations.

# COMMANDS

## Policy Management

**add *policy_name***  
Create a new policy.

**del *policy***  
Delete a policy.

**show \[*policy*\]**  
Display policy information. Without arguments, shows all policies.

**list \[*regex*\]**  
List policies, optionally filtered by regex pattern.

**enable *policy***  
Enable a disabled policy.

**disable *policy***  
Disable a policy without deleting it.

**rename *policy* *new_name***  
Rename a policy.

**move \[**--keep-acls**\] *policy* *unit***  
Move policy to a different unit.

## Policy Configuration

**show_config *policy* \[*parameter*\]**  
Show all policy configuration parameters.

**config \[**-d**\] *policy* *parameter* \[*value*\]**  
Set or display a configuration parameter. Use **-d** to delete (reset to
default).

**description *policy* \[*description*\]**  
Set policy description.

## Policy Assignment

Policies can be assigned to other policies (policy chaining):

**add_policy *policy* *child_policy***  
Add a policy to this policy.

**remove_policy *policy* *child_policy***  
Remove a policy from this policy.

**list_policies *policy***  
List policies assigned to this policy.

## ACL Management

**add_acl *policy* *owner_type* *owner* *acl***  
Add an access control entry. Owner type can be 'role' or 'token'.

**del_acl *policy* *acl***  
Remove an access control entry.

**show_acls *policy***  
Display all ACLs for the policy.

**enable_acl_inheritance *policy***  
Enable ACL inheritance from parent objects.

**disable_acl_inheritance *policy***  
Disable ACL inheritance.

## Import/Export

**export *policy***  
Export policy configuration to stdout.

# POLICY TYPE DETAILS

## Password Policy

Controls password and PIN requirements.

Commands:

> **password_min_len *policy* *length***  
> Set minimum password length.
>
> **pin_min_len *policy* *length***  
> Set minimum PIN length.
>
> **enable_require_number *policy***  
> Require at least one number in password.
>
> **disable_require_number *policy***  
> Disable number requirement.
>
> **enable_require_upper *policy***  
> Require at least one uppercase character.
>
> **disable_require_upper *policy***  
> Disable uppercase requirement.
>
> **enable_require_lower *policy***  
> Require at least one lowercase character.
>
> **disable_require_lower *policy***  
> Disable lowercase requirement.
>
> **enable_require_special *policy***  
> Require at least one special character.
>
> **disable_require_special *policy***  
> Disable special character requirement.
>
> **strength_checker *policy* *checker***  
> Set the password strength checker to use.
>
> **enable_strength_checker *policy***  
> Enable the strength checker.
>
> **disable_strength_checker *policy***  
> Disable the strength checker.
>
> **strength_checker_opts *policy* *options***  
> Set strength checker options.
>
> **test \[**--password** *password*\] \[**--pin** *pin*\] *policy***  
> Test the policy against a password or PIN.

## Login Times Policy

Restricts authentication to specific time windows.

Commands:

> **login_times *policy* *login_times***  
> Set allowed login times.
>
> **test \[**--object-type** *type*\] \[**--test-object** *object*\] \[**--token** *token*\] *policy***  
> Test the policy. Specify the object type, test object, and token to
> simulate.

## Auto-Disable Policy

Automatically disables accounts or tokens based on time or usage.

Commands:

> **auto_disable *policy* *time***  
> Set disable time. Can be an absolute time (e.g. "09:53 13.06.2023") or
> a relative duration (e.g. "1d" for 1 day). Use **-u** to disable after
> the object has been unused for the given time.

## Force Token Policy

Requires specific token types or pass types for authentication.

Commands:

> **force_token_types *policy* *token_types***  
> Set the list of allowed token types (e.g. totp, hotp, fido2).
>
> **force_pass_types *policy* *pass_types***  
> Set the list of allowed pass types.

## Auth On Action Policy

Requires re-authentication before performing sensitive operations.

Commands:

> **add_hook *policy* *object_type* *hook***  
> Add a hook that triggers re-authentication (e.g. change_pin).
>
> **remove_hook *policy* *object_type* *hook***  
> Remove a hook.
>
> **reauth_timeout *policy* *timeout***  
> Set the re-authentication timeout.
>
> **reauth_expiry *policy* *expiry***  
> Set the re-authentication expiry timeout.
>
> **whitelist_token *policy* *token***  
> Add a token to the re-authentication whitelist (exempt from re-auth).
>
> **unwhitelist_token *policy* *token***  
> Remove a token from the whitelist.
>
> **whitelist_role *policy* *role***  
> Add a role to the re-authentication whitelist.
>
> **unwhitelist_role *policy* *role***  
> Remove a role from the whitelist.

## Default Units Policy

Specifies default organizational units for new objects.

Commands:

> **set_unit *policy* *object_type* \[*unit*\]**  
> Set default unit for an object type (user, host, group, etc.). Omit
> unit to clear.

## Default Groups Policy

Automatically adds new users to specified groups and sets the user's
default (primary) group.

Commands:

> **add_group *policy* *group***  
> Add a default group.
>
> **remove_group *policy* *group***  
> Remove a default group.
>
> **default_group *policy* *group***  
> Set the primary default group.

## Default Roles Policy

Automatically adds a new user's default token to the specified roles.

Commands:

> **add_default_role *policy* *role***  
> Add a default role.
>
> **remove_default_role *policy* *role***  
> Remove a default role.

## Default Policies Policy

Automatically applies policies to new objects of a given type.

Commands:

> **add_default_policy *policy* *object_type* *policy_name***  
> Add a default policy for the given object type.
>
> **remove_default_policy *policy* *object_type* *policy_name***  
> Remove a default policy.

## ID Range Policy

Controls UID/GID allocation ranges.

Commands:

> **add_id_range *policy* *attribute:type:range***  
> Add an ID range. Range type must be s=sequence or r=random.
>
> **del_id_range *policy* *attribute:type:range***  
> Delete an ID range.
>
> **enable_id_check *policy***  
> Enable check if a new ID is already in use.
>
> **disable_id_check *policy***  
> Disable ID uniqueness check.
>
> **enable_id_range_recheck *policy***  
> Enable periodic ID range re-check.
>
> **disable_id_range_recheck *policy***  
> Disable ID range re-check.

## Token ACLs Policy

Defines default ACLs for users, tokens, and token creators.

Commands:

> **add_user_acl *policy* *acl***  
> Add a user ACL.
>
> **del_user_acl *policy* *acl***  
> Delete a user ACL.
>
> **add_token_acl *policy* *acl***  
> Add a token ACL.
>
> **del_token_acl *policy* *acl***  
> Delete a token ACL.
>
> **add_creator_acl *policy* *acl***  
> Add a token creator ACL.
>
> **del_creator_acl *policy* *acl***  
> Delete a token creator ACL.

## Object Templates Policy

Provides templates for creating new objects with predefined
configurations.

Commands:

> **set_template *policy* *object_type* *template***  
> Set a template for the given object type.

# OPTIONS

**--type *TYPE***  
Specify the policy type. Required for the **add** command and for all
type-specific commands. Must be placed before the command.

**--keep-acls**  
Preserve ACLs when moving policy to different unit.

## Display Options

**-a**  
Show all policies (not just current unit).

**-z *SIZE***  
Limit output size.

**--fields *FIELD1,FIELD2***  
Display only specified fields.

**--policy-limit *N***  
Limit number of policies shown.

Global options are available for all commands. See **otpme**(1) for
details.

# CONFIG PARAMETERS

Configuration parameters can be set with the **config** command and
displayed with **show_config**. For a complete description of all
available parameters and their applicable object types, see
**otpme**(7).

# EXAMPLES

## Password Policy

**otpme-policy --type password add strong_passwords**  
Create a password policy

**otpme-policy password_min_len strong_passwords 12**  
Require minimum 12 characters

**otpme-policy enable_require_upper strong_passwords**  
Require at least one uppercase letter

**otpme-policy enable_require_number strong_passwords**  
Require at least one number

**otpme-policy enable_require_special strong_passwords**  
Require at least one special character

**otpme-policy enable_strength_checker strong_passwords**  
Enable password strength checking

**otpme-policy test --password MyP@ss123 strong_passwords**  
Test a password against the policy

**otpme-user add_policy alice strong_passwords**  
Apply policy to user alice

## Login Time Restrictions

**otpme-policy --type logintimes add workhours**  
Create login times policy

**otpme-policy login_times workhours mon-fri 08:00-18:00**  
Set allowed login times

**otpme-group add_policy contractors workhours**  
Apply to contractors group

## Auto-Disable Temporary Access

**otpme-policy --type autodisable add temp_access**  
Create auto-disable policy

**otpme-policy auto_disable temp_access 90d**  
Auto-disable after 90 days

**otpme-policy auto_disable -u temp_access 30d**  
Auto-disable after 30 days of inactivity

**otpme-user add_policy temp_contractor temp_access**  
Apply to temporary contractor

## Force Two-Factor Authentication

**otpme-policy --type forcetoken add require_2fa**  
Create force token policy

**otpme-policy force_token_types require_2fa totp,fido2**  
Require TOTP or FIDO2 tokens

**otpme-accessgroup add_policy vpn_access require_2fa**  
Apply to VPN access group

## Protect Sensitive Operations

**otpme-policy --type authonaction add protect_ops**  
Create auth-on-action policy

**otpme-policy add_hook protect_ops user change_pin**  
Require re-auth for PIN changes

**otpme-policy reauth_timeout protect_ops 300**  
Re-auth valid for 5 minutes (300 seconds)

**otpme-policy whitelist_role protect_ops ADMIN**  
Exempt admin role from re-auth

## Set Organizational Defaults

**otpme-policy --type defaultunits add org_defaults**  
Create default units policy

**otpme-policy set_unit org_defaults user it/users**  
New users go to it/users unit

**otpme-policy set_unit org_defaults host infrastructure/servers**  
New hosts go to infrastructure/servers

## ID Ranges

**otpme-policy --type idrange add uid_range**  
Create ID range policy

**otpme-policy add_id_range uid_range uidNumber:s:10000-60000**  
Add sequential UID range 10000-60000

**otpme-policy enable_id_check uid_range**  
Enable ID uniqueness checking

# FILES

*/var/lib/otpme/objects/policy/*  
Server-side policy storage

# SEE ALSO

**otpme**(1), **otpme**(7), **otpme-user**(1), **otpme-group**(1),
**otpme-token**(1), **otpme-unit**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
