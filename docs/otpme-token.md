# NAME

otpme-token - manage OTPme authentication tokens

# SYNOPSIS

**otpme-token** \[**--type** *token_type*\] *command* \[*options*\]
\[*token*\]

# DESCRIPTION

**otpme-token** manages authentication tokens in the OTPme system.
Tokens are credentials assigned to users. They are identified by their
path: *user*/*token_name* (e.g. alice/login).

# TOKEN TYPES

**hotp**  
HMAC-based One-Time Password (RFC 4226).

**totp**  
Time-based One-Time Password (RFC 6238).

**password**  
Static password authentication.

**ssh**  
SSH public key authentication.

**fido2**  
FIDO2/WebAuthn hardware authentication.

**u2f**  
U2F hardware authentication.

**yubikey_hmac**  
YubiKey HMAC-SHA1 challenge-response authentication.

**yubikey_hotp**  
YubiKey OATH HOTP authentication.

**yubikey_gpg**  
YubiKey GPG applet authentication.

**motp**  
Mobile OTP (mOTP).

**otp_push**  
Push notification-based OTP.

**link**  
Link to another user's token.

# COMMANDS

## Token Management

**add \[**-r**\] *token***  
Add a new token. Requires **--type** before the command.

For **hotp** and **totp** tokens the following extra options are
available:

--mode mode  
Token mode. Defaults to **mode2**. In **mode2** neither the OTP secret
nor the PIN are stored in the token object; the effective OTP secret is
derived from the server-side secret together with the PIN. This mode is
compatible with the SSO portal, but changing the PIN requires
redeploying the token (a new QR code must be scanned). In **mode1** the
OTP secret is stored directly in the token object, so PIN changes do not
require redeployment.

--no-qrcode  
Do not display the QR code on token creation.

**del *token***  
Delete a token.

**show \[*token*\]**  
Display token information.

**list \[*regex*\]**  
List tokens, optionally filtered by regex pattern.

**enable \[**--share-notify**\|**--no-share-notify**\] \[**--no-persist-mount**\] *token***  
Enable a disabled token.

**--share-notify**  
Send notification to all online hosts on new share permissions.

**--no-share-notify**  
Do not send notification to all online hosts on new share permissions.

**--no-persist-mount**  
Do not persist new share mounts on hosts.

**disable \[**--share-notify**\|**--no-share-notify**\] \[**--no-persist-mount**\] *token***  
Disable a token without deleting it.

**--share-notify**  
Send notification to all online hosts on revoked share permissions.

**--no-share-notify**  
Do not send notification to all online hosts on revoked share
permissions.

**--no-persist-mount**  
Keep persisted share mounts on hosts (transient unmount only).

**rename *token* *new_name***  
Rename a token.

**move \[**-r**\] *token* *new_token_path***  
Move token to another user. Use **-r** to replace existing token keeping
its UUID.

**touch *token***  
Re-index the object to fix potential index problems.

## Token Configuration

**config \[**-d**\] \[**-a**\] *token* *parameter* \[*value*\]**  
Set a configuration parameter. Use **-d** to delete (reset to default)
or **-a** to append the value to a list-typed parameter.

**show_config *token* \[*parameter*\]**  
Show all configuration parameters.

**get_config *token* *parameter***  
Show the value of a single configuration parameter.

**auto_disable \[**-u**\] *token* *time***  
Set auto-disable time (e.g. "1d" or "09:53 13.06.2023"). Use **-u** to
disable if unused for the given time.

**description *token* \[*description*\]**  
Set token description.

**info \[**--language** *LANG*\] *token* \[*info*\]**  
Set free-form info text. If *info* is omitted, the current info text is
opened in the editor specified by the **EDITOR** environment variable.

**dump_info \[**--language** *LANG*\] *token***  
Dump the info text to stdout.

**test *token* \[*otp\|password*\]**  
Test if given OTP/password can be verified by the token.

**temp_password \[**--generate**\] \[**--duration** *time*\] \[**--remove**\] \[**--weak-password**\] *token* \[*password*\]**  
Set, generate or remove a temporary password. With **--weak-password** a
password the password policy rejects is accepted, which needs the
*force_password* ACL. This is not the same as **-f**, which only skips
the confirmation.

## VLAN Assignment

A token is not assigned a VLAN with a command of its own. Either the
VLAN names the token, so that the assignment belongs to the site that
runs the network (see **otpme-vlan**(1)):

> **otpme-vlan add_token *vlan* *user***/***token***

or the token names the VLAN through its **vlans** config parameter (see
**otpme**(7)):

> **otpme-token config *user***/***token* vlans *vlan***

The VLAN is returned during 802.1x port authentication. Membership wins:
the **vlans** parameter is only looked at when no VLAN of the site
answering the RADIUS request names the token or a role it is in. The
more specific assignment wins, so a VLAN naming the token itself
overrides the VLAN of its role.

## Offline Configuration

**enable_offline *token***  
Enable offline usage (caching) of token.

**disable_offline *token***  
Disable offline usage (caching) of token.

**offline_expiry *token* *expiry***  
Set offline expiry timeout.

**offline_unused_expiry *token* *expiry***  
Set offline unused expiry timeout.

## Session

**enable_session_keep *token***  
Enable keeping of login session (e.g. on shutdown).

**disable_session_keep *token***  
Disable keeping of login session.

## Auth Script

**auth_script *token* *script***  
Change token authorization script.

**enable_auth_script *token***  
Enable token authorization script.

**disable_auth_script *token***  
Disable token authorization script.

## Deploy

Hardware tokens must be deployed before use. Deployment configures the
physical device and registers the token in OTPme. Use **--type** before
the command to specify the token type.

**deploy **--list-token-types****  
List deployable token types.

## Deploy - FIDO2 and U2F

**deploy \[**-d**\] \[**-r**\] \[**--no-pin**\] \[**--uv** *uv*\] *token***  
Register a FIDO2 or U2F hardware key. The device must be connected and
will prompt for a touch.

**--no-pin**  
Do not set a PIN on the FIDO2 authenticator during deploy.

**--uv *uv***  
Set the FIDO2 user verification requirement (**discouraged**,
**preferred**, **required**). See also the **uv** command below.

**-r**  
Replace existing token (keep UUID).

**-d**  
Enable debug output.

## Deploy - YubiKey HMAC-SHA1

**deploy \[**-d**\] \[**-r**\] \[**-n**\] \[**-s** *slot*\] \[*token*\]**  
Write HMAC-SHA1 configuration to a YubiKey slot.

**-s *slot***  
Write configuration to the given YubiKey slot.

**-n**  
Do not reconfigure the YubiKey hardware — only register token data in
OTPme.

**-r**  
Replace existing token (keep UUID).

**-d**  
Enable debug output.

## Deploy - YubiKey OATH HOTP

**deploy \[**-d**\] \[**-r**\] \[**-s** *slot*\] \[*token*\]**  
Write OATH HOTP configuration to a YubiKey slot.

**-s *slot***  
Write configuration to the given YubiKey slot.

**-r**  
Replace existing token (keep UUID).

**-d**  
Enable debug output.

## Deploy - YubiKey GPG Applet

**deploy \[**-d**\] \[**-r**\] \[**-n**\] \[**--backup** *file*\] \[**--restore** *file*\] \[*token*\]**  
Initialize the GPG applet on a YubiKey and generate RSA keys. Prompts
for real name, email, PIN and Admin PIN. Default backup path:
*/dev/shm/\<username\>.gpg*.

**--backup *file***  
Write GPG backup to *file*.

**--restore *file***  
Restore GPG configuration from backup *file*.

**-n**  
Do not initialize the GPG applet — only register token data in OTPme.

**-r**  
Replace existing token (keep UUID).

**-d**  
Enable debug output.

## Deploy - YubiKey PIV Applet

**deploy \[**-d**\] \[**-r**\] \[**-n**\] \[**--key-len** *bits*\] \[**--sign-algo** *algo*\] \[**--encrypt-algo** *algo*\] \[**--backup** *file*\] \[**--restore** *file*\] \[**--restore-from-server**\] \[**--backup-key-file** *file*\] \[**--add-user-key**\] \[*token*\]**  
Initialize the PIV applet on a YubiKey and generate the sign and encrypt
keys. Default backup path: */dev/shm/\<username\>\_\<token\>.pem*.

**--key-len *bits***  
Generate RSA key with the given key length in bits (only when the chosen
algo is RSA).

**--sign-algo *algo***  
Algorithm for the sign slot 9A: **rsa** (default) or **ed25519** (needs
YubiKey FW 5.7+).

**--encrypt-algo *algo***  
Algorithm for the encrypt slot 9D: **rsa** (default) or **x25519**
(needs YubiKey FW 5.7+).

**--backup *file***  
Write key backup to *file*.

**--restore *file***  
Restore key from backup *file*.

**--restore-from-server**  
Restore key from an existing token on the server. Requires
**--backup-key-file**.

**--backup-key-file *file***  
Backup key file used to decrypt the private key backup when restoring
from server.

**--add-user-key**  
Register the token's RSA public key as the user's public key.

**-n**  
Do not initialize the PIV applet — only register token data in OTPme.

**-r**  
Replace existing token (keep UUID).

**-d**  
Enable debug output.

## Dynamic Groups

**add_dynamic_group *token* *group***  
Add a dynamic group to the token.

**remove_dynamic_group *token* *group***  
Remove a dynamic group from the token.

**list_dynamic_groups *token***  
List dynamic groups of the token.

## Listing

**list_roles \[**--return-type** *TYPE*\] \[**-r**\] *token***  
List roles assigned to the token. Use **-r** for recursive listing. Use
**--return-type** to select the attribute returned (**name**,
**read_oid**, **full_oid**, **uuid**).

**list_hosts \[**--return-type** *TYPE*\] *token***  
List hosts this token is assigned to. Use **--return-type** to select
the attribute returned (**name**, **read_oid**, **full_oid**, **uuid**).

**list_nodes \[**--return-type** *TYPE*\] *token***  
List nodes this token is assigned to. Use **--return-type** to select
the attribute returned (**name**, **read_oid**, **full_oid**, **uuid**).

**list_groups \[**--return-type** *TYPE*\] *token***  
List groups this token is assigned to. Use **--return-type** to select
the attribute returned (**name**, **read_oid**, **full_oid**, **uuid**).

**list_accessgroups \[**--return-type** *TYPE*\] *token***  
List access groups this token is assigned to. Use **--return-type** to
select the attribute returned (**name**, **read_oid**, **full_oid**,
**uuid**).

**list_acls *token***  
Show ACLs assigned to the token.

**list_scopes \[**--return-type** *TYPE*\] *token***  
List OIDC scopes the token is assigned to.

**list_shares \[**--return-type** *TYPE*\] *token***  
List shares the token has access to.

## Object Changelog

**changelog *token***  
Show the object's changelog (chronological list of changes with author,
timestamp and optional custom text passed via **--changelog**).

**edit_changelog *token* *changelog_id***  
Open the given changelog entry in the editor named by **EDITOR** to edit
its custom text.

**del_changelog *token* *changelog_id***  
Remove a single entry from the object's changelog.

**clear_changelog *token***  
Clear the object's entire changelog.

## Policy Management

**add_policy *token* *policy***  
Attach a policy to the token.

**remove_policy *token* *policy***  
Remove a policy from the token.

**list_policies \[**--return-type** *TYPE*\] \[**--policy-types** *t1,t2*\] *token***  
List policies attached to the token. Use **--return-type** to select the
attribute returned (**name**, **read_oid**, **full_oid**, **uuid**) and
**--policy-types** to filter by policy type.

## ACL Management

**add_acl *token* *owner_type* *owner* *acl***  
Add an access control entry.

**del_acl *token* *acl***  
Remove an access control entry.

**show_acls *token***  
Display all ACLs for the token.

**enable_acl_inheritance *token***  
Enable ACL inheritance from parent objects.

**disable_acl_inheritance *token***  
Disable ACL inheritance.

## Import/Export

**export *token***  
Export token configuration to stdout.

**dump_token_data *token***  
Dump the token's authentication data (secret, hashes, counters, keys,
etc.) as JSON. Useful for copying credentials between two tokens of the
same type. Available on all token types that support it (HOTP, TOTP,
mOTP, password, SSH, FIDO2, U2F, passkey, YubiKey HMAC, YubiKey PIV,
...).

**set_token_data *token* *file***  
Load token authentication data previously produced by
**dump_token_data** back into a token of the same type.

**remove_orphans *token***  
Remove orphaned object references.

# TOKEN TYPE COMMANDS

The following commands require **--type** before the command.

## HOTP / TOTP / mOTP (OTP Tokens)

**secret *token* \[*secret*\]**  
Change token secret.

**show_secret *token***  
Show token secret.

**pin \[**--generate**\] *token* \[*pin*\]**  
Change token PIN.

**show_pin *token***  
Show token PIN.

**enable_pin *token***  
Enable token PIN. (HOTP/TOTP only)

**disable_pin *token***  
Disable token PIN. (HOTP/TOTP only)

**gen *token***  
Generate token OTP.

**gen_mschap *token***  
Generate MSCHAP challenge/response from token OTP.

**gen_qrcode *token***  
Generate QR code for token configuration. (HOTP/TOTP only)

**mode *token* *mode***  
Change token operation mode. (HOTP/TOTP only)

## HOTP Specific

**counter_check_range *token* \[*range*\]**  
Change OTP counter check range.

**resync *token* \[*otp*\]**  
Resync counter-based token.

**get_token_counter *token***  
Get token counter value.

## mOTP Specific

**validity_time *token* \[*time*\]**  
Change OTP validity time.

**timedrift_tolerance *token* \[*tolerance*\]**  
Change OTP timedrift tolerance.

## Password Token

**password \[**--generate**\] \[**--weak-password**\] *token* \[*password*\]**  
Change token password. With **--weak-password** a password the password
policy rejects is accepted, which needs the *force_password* ACL. This
is not the same as **-f**, which only skips the confirmation.

**2f_token *token* *second_factor_token***  
Change second factor token.

**enable_2f *token***  
Enable second factor token.

**disable_2f *token***  
Disable second factor token.

**enable_mschap *token***  
Enable MSCHAP authentication.

**disable_mschap *token***  
Disable MSCHAP authentication.

**remove_nt_hash *token***  
Remove NT hash used for MSCHAP authentication.

**upgrade_pass_hash *token* \[*hash_type*\] \[*args*\]**  
Upgrade password hash.

**gen_mschap *token***  
Generate an MSCHAP challenge/response pair from the token's
second-factor token.

**enable_sso_deploy *token* \[*deploy_token_type*\]**  
Enable first-login deployment of the token via the SSO portal. Optional
*deploy_token_type* pre-selects the token type to deploy.

**disable_sso_deploy *token***  
Disable SSO first-login deployment for the token.

## SSH Token

**ssh_public_key *token* \[*ssh_public_key*\]**  
Change token SSH public key.

**card_type *token* \[*card_type*\]**  
Set card type of SSH token (e.g. gpg).

**key_type *token* *key_type***  
Set SSH key type (e.g. rsa).

**password \[**--generate**\] \[**--weak-password**\] *token* \[*password*\]**  
Change token password. With **--weak-password** a password the password
policy rejects is accepted, which needs the *force_password* ACL. This
is not the same as **-f**, which only skips the confirmation.

**2f_token *token* *second_factor_token***  
Change second factor token.

**enable_2f / disable_2f *token***  
Enable/disable second factor token.

**get_sign_data \[**--tags** *tag1,tag2*\] *token***  
Get the object data that has to be signed (used by external signing
helpers).

SSH tokens also support signature commands: **sign**, **resign**,
**verify_sign**, **get_sign**, **add_sign**, **del_sign**.

## Link Token

**add *token* *destination_token***  
Add a link token pointing to destination_token.

## YubiKey HMAC

**otp_format *token* \[*format*\]**  
Change token OTP format.

**validity_time *token* \[*time*\]**  
Change OTP validity time.

**timedrift_tolerance *token* \[*tolerance*\]**  
Change OTP timedrift tolerance.

**mode *token* *mode***  
Change token operation mode.

**secret *token* \[*secret*\]**  
Change the token secret.

**show_secret *token***  
Show the token secret.

**gen *token***  
Generate a token OTP.

**gen_mschap *token***  
Generate an MSCHAP challenge/response pair from a token OTP.

**enable_mschap *token* / **disable_mschap** *token***  
Enable / disable MSCHAP authentication.

**remove_nt_hash *token***  
Remove the NT hash used for MSCHAP authentication.

## OTP Push Token

**password \[**--generate**\] \[**--weak-password**\] *token* \[*password*\]**  
Change the token password (used for the push confirmation channel).

**enable_mschap *token* / **disable_mschap** *token***  
Enable / disable MSCHAP authentication.

**remove_nt_hash *token***  
Remove the NT hash used for MSCHAP authentication.

## FIDO2

**uv *token* *uv***  
Set the FIDO2 user verification requirement (**discouraged**,
**preferred**, **required**).

## YubiKey PIV

**sign_public_key *token* \[*public_key*\]**  
Set the PIV token's sign public key.

**encrypt_public_key *token* \[*public_key*\]**  
Set the PIV token's encrypt public key.

**dump_sign_key *token***  
Dump the PIV token's sign public key (or backup pointer) to stdout.

**dump_encrypt_key *token***  
Dump the PIV token's encrypt public key (or backup pointer) to stdout.

**dump_private_key_backup *token***  
Dump the encrypted private-key backup for the PIV token to stdout (for
later **otpme-token deploy --restore**).

**sign \[*options*\] *token***  
Sign an object with the PIV token.

**resign \[*options*\] *token***  
Re-sign an existing signature with the PIV token.

**verify_sign \[*options*\] *token***  
Verify a signature made by the PIV token.

**get_sign *token***  
Show a signature stored on the PIV token.

**get_sign_data \[**--tags** *tag1,tag2*\] *token***  
Get the object data that needs to be signed by the PIV token.

**add_sign *token* *signature***  
Attach an externally created signature to the PIV token.

**del_sign *token* *signature***  
Remove a signature from the PIV token.

# OPTIONS

**--type *TYPE***  
Specify the token type. Required for the **add** command and for all
type-specific commands. Must be placed before the command.

## Display Options

**-a**  
Show all tokens.

**-z *SIZE***  
Limit output size.

**--fields *FIELD1,FIELD2***  
Display only specified fields.

**--role-limit *N***  
Limit number of roles shown.

**--policy-limit *N***  
Limit number of policies shown.

**--limit *N***  
Limit number of items shown per object.

## General Options

**-r**  
Replace existing token and keep its UUID (for add, move, deploy).

**-u**  
Disable if unused for the given time (auto_disable).

Global options are available for all commands. See **otpme**(1) for
details.

# CONFIG PARAMETERS

Configuration parameters can be set with the **config** command und
displayed with **show_config**. For a complete description of all
available parameters and their applicable object types, see
**otpme**(7).

# EXAMPLES

**otpme-token --type totp add alice/totp**  
Create a TOTP token for user alice

**otpme-token --type fido2 deploy alice/fido2**  
Deploy a FIDO2 token

**otpme-token test alice/totp**  
Test token authentication

**otpme-token --type link add root/admin_link alice/login**  
Create a link token

**otpme-vlan add_token servers alice/totp**  
Put the token into a VLAN, whatever VLAN its roles are in

**otpme-token config alice/totp vlans guests**  
Assign a VLAN to the token, used where no VLAN names it

# FILES

*/var/lib/otpme/*  
OTPme data directory

# SEE ALSO

**otpme**(1), **otpme**(7), **otpme-user**(1), **otpme-role**(1),
**otpme-policy**(1), **otpme-accessgroup**(1), **otpme-vlan**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
