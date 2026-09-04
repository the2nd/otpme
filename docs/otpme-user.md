# NAME

otpme-user - manage OTPme user accounts

# SYNOPSIS

**otpme-user** *command* \[*options*\] \[*user*\]

# DESCRIPTION

**otpme-user** manages user accounts in the OTPme authentication system.
Users are identities that can authenticate to the system using tokens
(OTP, SSH keys, passwords, etc.). Users can be members of groups,
assigned roles, and have policies applied to control their access.

Users are identified by their name within the organizational unit
hierarchy (e.g., alice, bob, it/admin_user).

# COMMANDS

## User Management

**add \[*options*\] *username***  
Create a new user account. By default, creates a user with a default
token.

**del *user* \[*user* ...\]**  
Delete one or more user accounts.

**show \[*user*\]**  
Display user information. Without arguments, shows all users.

**list \[*regex*\]**  
List users, optionally filtered by regex pattern.

**enable \[**--share-notify**\|**--no-share-notify**\] \[**--no-persist-mount**\] *user***  
Enable a disabled user account.

**--share-notify**  
Send notification to all online hosts on new share permissions.

**--no-share-notify**  
Do not send notification to all online hosts on new share permissions.

**--no-persist-mount**  
Do not persist new share mounts on hosts.

**disable \[**--share-notify**\|**--no-share-notify**\] \[**--no-persist-mount**\] *user***  
Disable a user account without deleting it.

**--share-notify**  
Send notification to all online hosts on revoked share permissions.

**--no-share-notify**  
Do not send notification to all online hosts on revoked share
permissions.

**--no-persist-mount**  
Keep persisted share mounts on hosts (transient unmount only).

**rename *user* *new_name***  
Rename a user account.

**move \[**--keep-acls**\] *user* *unit***  
Move user to a different organizational unit.

**touch *user***  
Re-index the object to fix potential index problems.

**auto_disable \[**-u**\] *user* *time***  
Set auto-disable time (e.g. "1d" or "09:53 13.06.2023"). Use **-u** to
disable if unused for the given time.

**enable_auto_mount *user***  
Enable auto-mount for user.

**disable_auto_mount *user***  
Disable auto-mount for user.

**enable_admin_access *user***  
Enable admin access (temporary-password self-service) for the user via
the SSO portal. Sets the **allow_temp_passwords** config parameter and
grants the **set_temp_password** ACL for the role resolved from the
user's **admin_access_role** cascade. Errors if **admin_access_role** is
unset or the role cannot be resolved.

**disable_admin_access *user***  
Disable admin access for the user: clear **allow_temp_passwords**,
revoke the **set_temp_password** ACL for the **admin_access_role** role,
and purge any active temporary password from every token that still has
one.

## Token Management

**add_token \[**-r**\] \[**--no-qrcode**\] \[**--enable-mschap**\] \[**--token-type** *TYPE*\] \[**--name** *NAME*\] \[**--destination** *DST*\] \[**--password** *PASS*\] \[**--weak-password**\] *user***  
Add a new token to the user. **-r** replaces an existing token of the
same name while keeping its UUID (useful when re-running setup).

**del_token *user* *token***  
Delete a token from the user.

**list_tokens \[**--return-type** *TYPE*\] \[**--token-types** *t1,t2*\] \[*user*\]**  
List all tokens assigned to user(s). Use **--return-type** to select the
attribute returned (**name**, **read_oid**, **full_oid**, **uuid**) and
**--token-types** to filter by token type.

**deploy_token *user* *token***  
Deploy the token (e.g. a smartcard token).

## Group Membership

**group *user* *group***  
Change the user's default group. (A user is added to further groups from
the group side; see **otpme-group**(1).)

**list_groups \[**--return-type** *TYPE*\] \[*user*\]**  
List groups the user belongs to. Use **--return-type** to select the
attribute returned (**name**, **read_oid**, **full_oid**, **uuid**).

## Role Membership

Roles are managed from the role side; see **otpme-role**(1).

**list_roles \[**--return-type** *TYPE*\] \[*user*\]**  
List roles assigned to the user. Use **--return-type** to select the
attribute returned (**name**, **read_oid**, **full_oid**, **uuid**).

## Policy Management

**add_policy *user* *policy***  
Attach a policy to the user.

**remove_policy *user* *policy***  
Remove a policy from the user.

**list_policies \[**--return-type** *TYPE*\] \[**--policy-types** *t1,t2*\] \[*user*\]**  
List policies attached to the user. Use **--return-type** to select the
attribute returned (**name**, **read_oid**, **full_oid**, **uuid**) and
**--policy-types** to filter by policy type.

## User Configuration

**config \[**-d**\] \[**-a**\] *user* *parameter* \[*value*\]**  
Set a configuration parameter. Use **-d** to delete (reset to default)
or **-a** to append the value to a list-typed parameter.

**show_config *user* \[*parameter*\]**  
Show all configuration parameters.

**get_config *user* *parameter***  
Show the value of a single configuration parameter.

**description *user* \[*description*\]**  
Set user description.

**language *user* *language***  
Set the user's localization language (e.g. "en", "de").

**enable_disabled_login *user***  
Allow the user to log in even if the accessgroup is disabled.

**disable_disabled_login *user***  
Undo **enable_disabled_login**.

**unblock *user* \[*accessgroup*\]**  
Unblock the user for the given accessgroup, or for all accessgroups if
none is given.

**enable_auto_mount *user* / **disable_auto_mount** *user***  
See *SS User Management* above.

**enable_autosign *user***  
Enable the auto-sign feature of the user.

**disable_autosign *user***  
Disable the auto-sign feature of the user.

## User Scripts

**auth_script *user* *script* **--** \[*script_options*\]**  
Set the user's authorization script.

**enable_auth_script *user* / **disable_auth_script** *user***  
Enable / disable the user's authorization script.

**key_script *user* \[*script*\] **--** \[*script_options*\]**  
Set the user's key script.

**get_key_script *user* \[**name**\|**uuid**\]**  
Show the name or UUID of the user's key script.

**agent_script *user* \[*script*\] **--** \[*script_options*\]**  
Set the user's agent script.

**login_script *user* \[*script*\] **--** \[*script_options*\]**  
Set the user's login script.

**enable_login_script *user* / **disable_login_script** *user***  
Enable / disable the user's login script.

## VLAN Assignment

A user is never the object of a port authentication -- a token is. So a
user has no VLAN of its own, and cannot be made a member of one. What it
can do is set the default for its tokens through the **vlans** config
parameter (see **otpme**(7)):

> **otpme-user config *user* vlans *vlan***

A token without a **vlans** parameter of its own inherits this one, the
same way it inherits any other config parameter from its user, its unit
and its site.

It only decides where no VLAN of the site answering the RADIUS request
names the token or a role it is in, because membership always wins. To
give a person a VLAN that way, put their token or one of their roles
into it (see **otpme-vlan**(1)).

## Cryptographic Keys

**gen_keys \[*options*\] *user***  
Generate the user's sign and encrypt RSA key pairs.

**del_keys *user***  
Delete the user's cryptographic keys.

**gen_cert \[**--stdin-pass**\] *user***  
Generate a certificate for the user.

**key_mode *user* *mode***  
Set key mode (**client** or **server**).

**get_key_mode *user***  
Display current key mode.

**get_sign_key_type *user***  
Show the user's sign key type.

**get_enc_key_type *user***  
Show the user's encrypt key type.

**key_cache_time *user* *time***  
Set how long otpme-agent may cache the users private key, e.g. how long
it keeps the yubikey PIV handler open after the PIN was entered. Accepts
a plain number of seconds or a time string such as *5m*. The default *0*
means no timeout, the key stays cached as long as the agent runs. The
agent gets the value with the login session, so a change takes effect on
the next login.

**key_pass *user***  
Change key passphrase.

**sign_private_key *user* *private_key***  
Set the user's sign private key.

**encrypt_private_key *user* *private_key***  
Set the user's encrypt private key.

**sign_public_key *user* *public_key***  
Set the user's sign public key.

**encrypt_public_key *user* *public_key***  
Set the user's encrypt public key.

**import_sign_key \[**--server**\] \[**-n**\] \[**--stdin-key**\] *user* \[*private_key_file*\]**  
Import the user's sign RSA key. **-n** stores the private key
unencrypted, **--server** keeps it on the server.

**import_encrypt_key \[**--server**\] \[**-n**\] \[**--stdin-key**\] *user* \[*private_key_file*\]**  
Import the user's encrypt RSA key. Flags as for **import_sign_key**.

**dump_sign_key \[**-p**\] \[**-n**\] \[**--stdin-pass**\] *user***  
Dump the user's sign key to stdout. **-p** dumps the private key (or a
pointer to it), **-n** dumps it unencrypted if possible.

**dump_encrypt_key \[**-p**\] \[**-n**\] \[**--stdin-pass**\] *user***  
Dump the user's encrypt key to stdout. Flags as for **dump_sign_key**.

## Object Changelog

**changelog *user***  
Show the object's changelog (chronological list of changes with author,
timestamp and optional custom text passed via **--changelog**).

**edit_changelog *user* *changelog_id***  
Open the given changelog entry in the editor named by **EDITOR** to edit
its custom text.

**del_changelog *user* *changelog_id***  
Remove a single entry from the object's changelog.

**clear_changelog *user***  
Clear the object's entire changelog.

## ACL Management

**add_acl *user* *owner_type* *owner* *acl***  
Add an access control entry.

**del_acl *user* *acl***  
Remove an access control entry.

**show_acls *user***  
Display all ACLs for the user.

**enable_acl_inheritance *user***  
Enable ACL inheritance from parent objects.

**disable_acl_inheritance *user***  
Disable ACL inheritance.

## LDAP Integration

**add_attribute \[**-i** *position*\] *user* *attribute*=\[*value*\]**  
Add an LDAP attribute to the user. Use **-i** to insert a multi-value
attribute at the given zero-based position.

**del_attribute *user* *attribute*=*value***  
Remove an LDAP attribute from the user.

**modify_attribute *user* *attribute* *old_value* *new_value***  
Change an LDAP attribute value.

**add_object_class *user* *class***  
Add an LDAP object class to the user.

**del_object_class *user* *class***  
Remove an LDAP object class from the user.

**show_ldif *user***  
Display LDAP LDIF representation of the user.

**info \[**--language** *LANG*\] *user* \[*info*\]**  
Set free-form user info text. If *info* is omitted, the current info
text is opened in the editor specified by the **EDITOR** environment
variable.

**dump_info \[**--language** *LANG*\] *user***  
Dump the user info text to stdout.

## Extension Management

**add_extension *user* *extension***  
Add an extension to the user.

**remove_extension *user* *extension***  
Remove an extension from the user.

## User Photo

**photo *user* *image_path***  
Set the user's photo (JPEG).

**dump_photo *user***  
Dump the user's photo as base64 to stdout.

**del_photo *user***  
Remove the user's photo.

## Import/Export

**export \[**--password** *PASS*\] *user***  
Export user configuration. Use **--password** to encrypt.

**remove_orphans *user***  
Remove orphaned object references.

# OPTIONS

## User Creation Options

**--group *GROUP***  
Set the default group of the user.

**--groups *GROUP1,GROUP2***  
Add user to multiple groups during creation.

**--role *ROLE***  
Assign role during user creation.

**--roles *ROLE1,ROLE2***  
Assign multiple roles during user creation.

**--password *PASS***  
Set initial password during user creation.

**--weak-password**  
Accept a password even if the password policy would reject it. Needs the
**force_password** ACL on the target unit.

**--no-default-token**  
Do not create a default token for the user.

**--default-token *NAME***  
Specify name for the default token (default: "login").

**--default-token-type *TYPE***  
Specify type for the default token (default: system default).

**--no-qrcode**  
Do not generate default token QR code (TOTP/HOTP only).

**--mode *MODE***  
Mode for the default token (TOTP/HOTP only). See **otpme-token**(1) for
the difference between **mode1** and **mode2**.

**-t, --template**  
Create user as a template object.

**--template *NAME***  
Use specified template when creating user.

**--attributes *ATTR1=VAL1,ATTR2=VAL2***  
Set LDAP attributes during user creation.

## Key Generation Options

**-b *BITS***  
Specify key length in bits (default: 4096).

**--server**  
Generate server-mode keys.

**--pass-hash-type *TYPE***  
Specify password hash type.

**-n**  
Do not encrypt the private key.

**--stdin-pass**  
Read passphrase from stdin.

**--stdin-key**  
Read key from stdin.

## Display Options

**-a**  
Show all users (across all units).

**-t, --show-templates**  
Include template users in output.

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
Preserve ACLs when moving user.

**--password *PASS***  
Password for encrypting exports.

# CONFIG PARAMETERS

Configuration parameters can be set with the **config** command and
displayed with **show_config**. For a complete description of all
available parameters and their applicable object types, see
**otpme**(7).

# EXAMPLES

## Creating Users

**otpme-user add alice**  
Create user alice with default token

**otpme-user add --no-default-token bob**  
Create user bob without a default token

**otpme-user add --default-token-type totp charlie**  
Create user charlie with a TOTP token

**otpme-user add --group admins --role ADMIN dave**  
Create admin user dave

**otpme-user add --groups users,developers --roles DEV,USER eve**  
Create user eve with multiple groups and roles

## Managing Groups and Roles

**otpme-user group alice developers**  
Change alice's default group to developers

**otpme-group add_token developers alice/login**  
Add one of alice's tokens to the developers group (group membership is
granted per token, see **otpme-group**(1))

**otpme-role add_user DEVELOPER alice/login**  
Assign the DEVELOPER role to one of alice's tokens (managed from the
role side, see **otpme-role**(1))

**otpme-user list_groups alice**  
Show alice's group memberships

**otpme-user list_roles alice**  
Show alice's assigned roles

## VLAN Assignment

**otpme-user config alice vlans guests**  
Set the VLAN her tokens use where no VLAN names them

**otpme-vlan add_token guests alice/totp**  
Put one of her tokens into a VLAN, which wins over the parameter above

## Applying Policies

**otpme-user add_policy alice strong_passwords**  
Apply password policy to alice

**otpme-user add_policy alice workhours_only**  
Restrict alice's login times

**otpme-user list_policies alice**  
Show all policies applied to alice

## Key Management

**otpme-user gen_keys alice**  
Generate encryption keys for alice

**otpme-user gen_keys -b 2048 bob**  
Generate 2048-bit keys for bob

**otpme-user key_pass alice**  
Change alice's key passphrase

**otpme-user dump_sign_key alice**  
Dump alice's sign public key

## Managing User Status

**otpme-user disable alice**  
Temporarily disable alice's account

**otpme-user enable alice**  
Re-enable alice's account

**otpme-user rename alice alice_temp**  
Rename user alice to alice_temp

**otpme-user move alice it/admins**  
Move alice to it/admins unit

## Querying Users

**otpme-user show alice**  
Show detailed information about alice

**otpme-user list**  
List all users in current unit

**otpme-user list -a**  
List all users in all units

**otpme-user list ^admin.\***  
List users starting with "admin"

**otpme-user show --fields name,uid,groups**  
Show users with specific fields

## Using Templates

**otpme-user add -t developer_template**  
Create a user template for developers

**otpme-user add --template developer_template bob**  
Create bob using the developer template

# SEE ALSO

**otpme**(7), **otpme-token**(1), **otpme-group**(1), **otpme-role**(1),
**otpme-policy**(1), **otpme-vlan**(1), **otpme-unit**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
