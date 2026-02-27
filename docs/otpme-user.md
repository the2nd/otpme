# OTPME-USER(1)

## NAME

otpme-user - manage OTPme user accounts

## SYNOPSIS

**otpme-user**
*command*
[*options*] [*user*]

## DESCRIPTION

**otpme-user**
manages user accounts in the OTPme authentication system. Users are identities that can authenticate to the system using tokens (OTP, SSH keys, passwords, etc.). Users can be members of groups, assigned roles, and have policies applied to control their access.

Users are identified by their name within the organizational unit hierarchy (e.g., alice, bob, it/admin_user).

## COMMANDS

### User Management

**add [*options*] *username***
:   Create a new user account. By default, creates a user with a default token.

**del *user* [*user* ...]**
:   Delete one or more user accounts.

**show [*user*]**
:   Display user information. Without arguments, shows all users.

**list [*regex*]**
:   List users, optionally filtered by regex pattern.

**enable *user***
:   Enable a disabled user account.

**disable *user***
:   Disable a user account without deleting it.

**rename *user* *new_name***
:   Rename a user account.

**move [**--keep-acls**] *user* *unit***
:   Move user to a different organizational unit.

**touch *user***
:   Re-index the object to fix potential index problems.

**auto_disable [**-u**] *user* *time***
:   Set auto-disable time (e.g. "1d" or "09:53 13.06.2023"). Use **-u** to disable if unused for the given time.

**enable_auto_mount *user***
:   Enable auto-mount for user.

**disable_auto_mount *user***
:   Disable auto-mount for user.

### Token Management

**list_tokens [*user*]**
:   List all tokens assigned to user(s).

### Group Membership

**add_group *user* *group***
:   Add user to a group.

**remove_group *user* *group***
:   Remove user from a group.

**list_groups [*user*]**
:   List groups the user belongs to.

### Role Management

**add_role *user* *role***
:   Assign a role to the user.

**remove_role *user* *role***
:   Remove a role from the user.

**list_roles [*user*]**
:   List roles assigned to the user.

### Policy Management

**add_policy *user* *policy***
:   Attach a policy to the user.

**remove_policy *user* *policy***
:   Remove a policy from the user.

**list_policies [*user*]**
:   List policies attached to the user.

### User Configuration

**config [**-d**] *user* *parameter* [*value*]**
:   Set or display a configuration parameter. Use **-d** to delete (reset to default).

**show_config *user* [*parameter*]**
:   Show all configuration parameters.

**description *user* [*description*]**
:   Set user description.

**unit *user* [*unit*]**
:   Display or change user's organizational unit.

### Cryptographic Keys

**gen_keys [*options*] *user***
:   Generate encryption/signing keys for the user.

**del_keys *user***
:   Delete user's cryptographic keys.

**key_mode *user* *mode***
:   Set key mode (client or server).

**get_key_mode *user***
:   Display current key mode.

**key_pass *user***
:   Change key passphrase.

**dump_key [**-p**] *user***
:   Export user's public key (**-p** for private key).

**import_key *user* [*keyfile*]**
:   Import existing key for the user.

### ACL Management

**add_acl *user* *owner_type* *owner* *acl***
:   Add an access control entry.

**del_acl *user* *acl***
:   Remove an access control entry.

**show_acls *user***
:   Display all ACLs for the user.

**enable_acl_inheritance *user***
:   Enable ACL inheritance from parent objects.

**disable_acl_inheritance *user***
:   Disable ACL inheritance.

### LDAP Integration

**add_attribute *user* *attribute*=*value***
:   Add an LDAP attribute to the user.

**del_attribute *user* *attribute*=*value***
:   Remove an LDAP attribute from the user.

**add_object_class *user* *class***
:   Add an LDAP object class to the user.

**del_object_class *user* *class***
:   Remove an LDAP object class from the user.

**show_ldif *user***
:   Display LDAP LDIF representation of the user.

### Extension Management

**add_extension *user* *extension***
:   Add an extension to the user.

**remove_extension *user* *extension***
:   Remove an extension from the user.

### Import/Export

**export [**--password** *PASS*] *user***
:   Export user configuration. Use **--password** to encrypt.

**remove_orphans *user***
:   Remove orphaned object references.

## OPTIONS

### User Creation Options

**--group *GROUP***
:   Set the default group of the user.

**--groups *GROUP1,GROUP2***
:   Add user to multiple groups during creation.

**--role *ROLE***
:   Assign role during user creation.

**--roles *ROLE1,ROLE2***
:   Assign multiple roles during user creation.

**--password *PASS***
:   Set initial password during user creation.

**--no-default-token**
:   Do not create a default token for the user.

**--default-token *NAME***
:   Specify name for the default token (default: "login").

**--default-token-type *TYPE***
:   Specify type for the default token (default: system default).

**--no-qrcode**
:   Do not generate QR code for default TOTP token.

**-t, --template**
:   Create user as a template object.

**--template *NAME***
:   Use specified template when creating user.

**--attributes *ATTR1=VAL1,ATTR2=VAL2***
:   Set LDAP attributes during user creation.

### Key Generation Options

**-b *BITS***
:   Specify key length in bits (default: 4096).

**--server**
:   Generate server-mode keys.

**--pass-hash-type *TYPE***
:   Specify password hash type.

**-n**
:   Do not encrypt the private key.

**--stdin-pass**
:   Read passphrase from stdin.

**--stdin-key**
:   Read key from stdin.

### Display Options

**-a**
:   Show all users (across all units).

**-t, --show-templates**
:   Include template users in output.

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
:   Preserve ACLs when moving user.

**--password *PASS***
:   Password for encrypting exports.

## CONFIG PARAMETERS

Configuration parameters can be set with the **config** command and displayed with **show_config**.
For a complete description of all available parameters and their applicable object types, see
[otpme(7)](otpme.7.md).

## EXAMPLES

### Creating Users

**otpme-user add alice**
:   Create user alice with default token

**otpme-user add --no-default-token bob**
:   Create user bob without a default token

**otpme-user add --default-token-type totp charlie**
:   Create user charlie with a TOTP token

**otpme-user add --group admins --role ADMIN dave**
:   Create admin user dave

**otpme-user add --groups users,developers --roles DEV,USER eve**
:   Create user eve with multiple groups and roles

### Managing Groups and Roles

**otpme-user add_group alice developers**
:   Add alice to developers group

**otpme-user add_role alice DEVELOPER**
:   Assign DEVELOPER role to alice

**otpme-user list_groups alice**
:   Show alice's group memberships

**otpme-user list_roles alice**
:   Show alice's assigned roles

### Applying Policies

**otpme-user add_policy alice strong_passwords**
:   Apply password policy to alice

**otpme-user add_policy alice workhours_only**
:   Restrict alice's login times

**otpme-user list_policies alice**
:   Show all policies applied to alice

### Key Management

**otpme-user gen_keys alice**
:   Generate encryption keys for alice

**otpme-user gen_keys -b 2048 bob**
:   Generate 2048-bit keys for bob

**otpme-user key_pass alice**
:   Change alice's key passphrase

**otpme-user dump_key alice**
:   Export alice's public key

### Managing User Status

**otpme-user disable alice**
:   Temporarily disable alice's account

**otpme-user enable alice**
:   Re-enable alice's account

**otpme-user rename alice alice_temp**
:   Rename user alice to alice_temp

**otpme-user move alice it/admins**
:   Move alice to it/admins unit

### Querying Users

**otpme-user show alice**
:   Show detailed information about alice

**otpme-user list**
:   List all users in current unit

**otpme-user list -a**
:   List all users in all units

**otpme-user list "^admin.*"**
:   List users starting with "admin"

**otpme-user show --fields name,uid,groups**
:   Show users with specific fields

### Using Templates

**otpme-user add -t developer_template**
:   Create a user template for developers

**otpme-user add --template developer_template bob**
:   Create bob using the developer template

## SEE ALSO

[otpme(7)](otpme.7.md),
[otpme-token(1)](otpme-token.md),
[otpme-group(1)](otpme-group.md),
[otpme-role(1)](otpme-role.md),
[otpme-policy(1)](otpme-policy.md),
[otpme-unit(1)](otpme-unit.md)

## AUTHOR

the2nd <the2nd@otpme.org>

## NOTE

This manual page was created with AI assistance.

## COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
