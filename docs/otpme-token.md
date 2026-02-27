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

**script_otp**  
OTP generation via external script.

**link**  
Link to another user's token.

# COMMANDS

## Token Management

**add *token***  
Add a new token. Requires **--type** before the command.

**del *token***  
Delete a token.

**show \[*token*\]**  
Display token information.

**list \[*regex*\]**  
List tokens, optionally filtered by regex pattern.

**enable *token***  
Enable a disabled token.

**disable *token***  
Disable a token without deleting it.

**rename *token* *new_name***  
Rename a token.

**move \[**-r**\] *token* *new_token_path***  
Move token to another user. Use **-r** to replace existing token keeping
its UUID.

**touch *token***  
Re-index the object to fix potential index problems.

## Token Configuration

**config \[**-d**\] *token* *parameter* \[*value*\]**  
Set or display a configuration parameter. Use **-d** to delete (reset to
default).

**show_config *token* \[*parameter*\]**  
Show all configuration parameters.

**auto_disable \[**-u**\] *token* *time***  
Set auto-disable time (e.g. "1d" or "09:53 13.06.2023"). Use **-u** to
disable if unused for the given time.

**description *token* \[*description*\]**  
Set token description.

**test *token* \[*otp\|password*\]**  
Test if given OTP/password can be verified by the token.

**temp_password \[**--generate**\] \[**--duration** *time*\] \[**--remove**\] *token* \[*password*\]**  
Set, generate or remove a temporary password.

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

**deploy \[**-d**\] \[**-r**\] *token***  
Register a FIDO2 or U2F hardware key. The device must be connected and
will prompt for a touch.

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

**deploy \[**-d**\] \[**-r**\] \[**-n**\] \[**--key-len** *bits*\] \[**--backup** *file*\] \[**--restore** *file*\] \[**--restore-from-server**\] \[**--backup-key-file** *file*\] \[**--add-user-key**\] \[*token*\]**  
Initialize the PIV applet on a YubiKey and generate an RSA key. Default
backup path: */dev/shm/\<username\>\_\<token\>.pem*.

**--key-len *bits***  
Generate RSA key with the given key length in bits.

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

**list_roles \[**-r**\] *token***  
List roles assigned to the token. Use **-r** for recursive listing.

**list_hosts *token***  
List hosts this token is assigned to.

**list_nodes *token***  
List nodes this token is assigned to.

**list_groups *token***  
List groups this token is assigned to.

**list_accessgroups *token***  
List access groups this token is assigned to.

## Policy Management

**add_policy *token* *policy***  
Attach a policy to the token.

**remove_policy *token* *policy***  
Remove a policy from the token.

**list_policies *token***  
List policies attached to the token.

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

**password \[**--generate**\] *token* \[*password*\]**  
Change token password.

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

**dump_pass_hash *token***  
Dump password hash.

**set_pass_hash *token* *file***  
Set password hash from file.

**upgrade_pass_hash *token* \[*hash_type*\] \[*args*\]**  
Upgrade password hash.

## SSH Token

**ssh_public_key *token* \[*ssh_public_key*\]**  
Change token SSH public key.

**card_type *token* \[*card_type*\]**  
Set card type of SSH token (e.g. gpg).

**key_type *token* *key_type***  
Set SSH key type (e.g. rsa).

**password \[**--generate**\] *token* \[*password*\]**  
Change token password.

**2f_token *token* *second_factor_token***  
Change second factor token.

**enable_2f / disable_2f *token***  
Enable/disable second factor token.

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

# FILES

*/var/lib/otpme/*  
OTPme data directory

# SEE ALSO

**otpme**(1), **otpme**(7), **otpme-user**(1), **otpme-role**(1),
**otpme-policy**(1), **otpme-accessgroup**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
