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

The type of a token is chosen when it is added and never changes:

> **otpme-token --type *type* add *user***/***name***

It is not the same as the smartcard type further down: the token type
says how OTPme checks a login, the smartcard type says which device a
token is deployed to.

**password**  
A static password.

**hotp**  
One-time password by counter (RFC 4226).

**totp**  
One-time password by time (RFC 6238), what the authenticator apps use.

**motp**  
Mobile OTP, an older scheme for phones without an app store.

**ssh**  
An SSH public key.

**fido2**  
A hardware security key, e.g. a YubiKey or a Nitrokey. It signs a
challenge, so nothing that can be typed is enough to sign in, and the
signature is bound to the site that asked — which is what makes it
phishing resistant.  
Next to **passkey** this is the type where OTPme keeps the credential
and hands it to the key at every login, and where the key is not asked
to verify the user. The login itself looks the same: name first, then
the key.

**passkey**  
The same thing without the extra piece of hardware: the device the user
already has keeps the credential. That is usually a phone or a notebook,
where the fingerprint sensor or the face camera does the checking, and
where the credential can be synced to the other devices of that user. A
hardware key can hold one as well.  
The credential is kept by the authenticator, together with who it
belongs to, and the authenticator always asks for the finger, the face
or the PIN before it signs. So a passkey carries both factors in one
step.  
The user name is still typed first: the login asks OTPme which
credentials that user has and offers only those. What a passkey saves is
the password, not the name.  
Registered from the SSO portal, see **otpme**(7).

**u2f**  
The predecessor of FIDO2, for keys that speak nothing newer.

**yubikey_hmac**  
A YubiKey that answers a challenge with HMAC-SHA1. It works offline,
which is what a notebook needs that is away from the realm.

**yubikey_piv**  
A YubiKey PIV applet that holds the user's sign and encrypt keys. This
is the type OTPme recommends: the keys are made on the token and stay
there, which is what encrypted shares, script and token signing, and
802.1X port authentication build on, see **otpme**(7).

**tiqr**  
Smartphone challenge-response via the tiqr app (OCRA, RFC 6287). The
browser shows a QR code, the phone answers it over its own connection,
and the browser is signed in without anything being typed. Enrolled from
the SSO portal, not with **otpme-token add**; see **otpme-site**(1) for
the site settings (**tiqr_secret**, **sso_allow_tiqr_deploy**,
**tiqr_challenge_expiry**) and **otpme-user**(1) for
**default_sso_token_name**. Note that tiqr is not phishing resistant:
nothing binds the response to the browser that asked, so a relayed
challenge yields the attacker a session. Use FIDO2 where that matters.

**otp_push**  
A one-time password OTPme makes and pushes to the user, e.g. by mail or
SMS. The script that delivers it is **default_otp_push_script** in
**otpme**(7).  
Not finished: where the push is sent to is still a value on the token,
not the phone number of the user.

**script_otp**  
A one-time password that a script of yours checks, not OTPme.

**script_static**  
The same for a static password.

**link**  
A token that points at another token, named as *user***/***name*.
Whoever signs in with it uses the credential of that token, which is how
one person's key or password works for a second account.  
Not every type may be the destination: **password**, **hotp**, **totp**,
**motp**, **ssh**, **fido2**, **yubikey_hmac**, **yubikey_piv**,
**script_otp** and **script_static** may, the others may not. A
**passkey**, a **u2f** token and a **tiqr** phone are bound to their
owner when they are registered, and a link to a link would only chain.

## Smartcard Types

These say which device a token is deployed to, and they are what the
**deploy** command works with: **fido2**, **u2f**, **yubikey_hmac**,
**yubikey_hotp**, **yubikey_gpg** and **yubikey_piv**.

Three of them share a name with a token type, and two do not:
**yubikey_hotp** deploys a **hotp** token to the OATH applet of a
YubiKey, and **yubikey_gpg** deploys an **ssh** token to its GPG applet.
Neither is a value for **--type**.

# COMMANDS

## Token Management

**--type *type* add \[**-r**\] *user***/***name***  
Add a token to a user.  
**--type** comes before the command, and it has to: the type decides
which arguments and options **add** takes, and OTPme reads it before it
parses the rest of the line. **-r** replaces a token of that name and
keeps its UUID, which is what a setup run does when it runs again.  
What each type adds to the line:

**link**  
**add ***user***/***name*** ***dest_user***/***dest_name* — the token it
points at.

**ssh**  
**add ***user***/***name* \[*public_key*\] — without a key the token is
added and the key set later.

**password**  
**--password** *password* sets it right away, **--weak-password** takes
one the password policy would refuse, and **--enable-mschap** keeps the
NT hash on the server so that MSCHAP logins work.

**hotp** and **totp**  
**--mode** *mode* and **--no-qrcode**, see below.

The other types take nothing beyond the token path.

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

**del \[**--no-trash**\] *token***  
Delete a token. It goes to the trash, from where **otpme-trash**(1) can
bring it back; **--no-trash** deletes it right away.

**show \[**-a**\] \[**-z** *N*\] \[**--fields** *F1,F2*\] \[**--limit** *N*\] \[**--policy-limit** *N*\] \[**--role-limit** *N*\] \[**--scope-limit** *N*\] \[*token*\]**  
Show the tokens, with their roles, scopes and policies.  
Without a token you get your own, i.e. the tokens of the user you are
signed in as. **-a** shows every token you may look at. The other
options are under **Display Options** below.

**list \[**-a**\] \[*regex*\]**  
List the token paths, and with a regex only those that match it, e.g.
**alice/\*** for the tokens of one user.  
You get the tokens you may change; **-a** adds those you may only look
at.

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
The default token of a user is only renamed where the config parameter
**allow_default_token_rename** says so, see **otpme**(7).

**move \[**-r**\] *token* *dst_user*\[**/***name*\]**  
Move a token to another user. The user has to be on the same site;
moving a token to another site does not work.  
**-r** replaces a token of that name at the destination and keeps its
UUID. Without it OTPme asks, and it says so when the token it would
replace is the default token of that user.  
Moving into the **TOKENSTORE** gives the token a name of its own,
*old_owner***:***name*, with a number appended where that is taken
already. A name of your own is refused there. Moving it back out again
takes the part behind the **:** as the name, unless you give one.

**touch *token***  
Re-index the object to fix potential index problems.

## Token Configuration

**config \[**-d**\] \[**-a**\] *token* *parameter* \[*value*\]**  
Set a configuration parameter on the token. **-a** appends the value to
a parameter that holds a list.  
**-d** removes the parameter from the token, or with a value only that
one value from a list. What the token gets afterwards is whatever the
user, the unit or the site say. See **CONFIG PARAMETERS** in
**otpme**(7).

**show_config *token* \[*parameter*\]**  
Show the parameters set on the token itself, or only the given one.

**get_config *token* *parameter***  
Show the value of one parameter the way OTPme reads it, i.e. after
looking at the token, the user, the unit and the site. So this answers
what applies, while **show_config** answers what was set here.

**auto_disable \[**-u**\] *token* *time***  
Set auto-disable time. It is either a relative time with a leading
**+**, e.g. **+30D**, or an absolute one, e.g. **"09:53 13.06.2023"**.
The units are **s**, **m**, **h**, **D**, **W**, **M** and **Y**, see
**otpme**(7). Use **-u** to disable the token if it was unused for the
given time.

**description *token* \[*description*\]**  
Set the description of the token. Without one OTPme asks and offers the
current text for editing.

**device_name *token* \[*device_name*\]**  
Set the name of the device this token lives on, e.g. the phone or the
security key it was registered with.  
The SSO portal asks the user for it when they add a token there and
shows it in the list, so that somebody with three security keys can tell
them apart.

**info \[**--language** *LANG*\] *token* \[*info*\]**  
Set the info text of the token. Without a text OTPme opens the current
one in the editor named by **EDITOR**.  
An info text is kept per language. **--language** says which one;
without it the text is stored under **info**, which is the note of the
administrator.

**dump_info \[**--language** *LANG*\] *token***  
Write the info text of that language to stdout.

**test *token***  
Check whether the token verifies. OTPme asks for the OTP or the
password; it is never given on the command line.  
It is the real verification, not a dry run: an OTP tested here is spent,
and the counter of a **hotp** token moves on.  
Almost every type has it. **passkey** and **tiqr** do not: both need a
browser and a device that answers it, which a command line cannot stand
in for.

**temp_password \[**--generate**\] \[**--duration** *time*\] \[**--remove**\] \[**--weak-password**\] *token* \[*password*\]**  
Give the token a second password that works for a while, next to the one
it has. It is meant for an administrator or the IT support who has to
work as that user for a time, e.g. to set up a notebook.  
**--generate** makes one up, **--duration** says how long it lives
(**1h** without it, time units as in **otpme**(7)), and **--remove**
takes it away again.  
Setting one needs the config parameter **allow_temp_passwords** and the
ACL **set_temp_password**, on the token or on the user above it.
Removing one always works. On a **link** token the password is set on
the token it points at.  
**--weak-password** accepts a password the password policy rejects,
which needs the **force_password** ACL. This is not the same as **-f**,
which only skips the confirmation.

## VLAN Assignment

A token has no VLAN command of its own. The way to give it one is to put
it, or a role it is in, into the VLAN:

> **otpme-vlan add_token *vlan* *user***/***token***

That is the assignment that counts. A VLAN of the site answering the
RADIUS request that names the token, or a role the token is in, decides
the answer, and nothing below is asked any more. The nearer assignment
wins: a VLAN naming the token itself beats one naming its role, see
**otpme-vlan**(1).

Only where no such VLAN names the token does OTPme ask the **vlans**
config parameter (see **otpme**(7)):

> **otpme-token config *user***/***token* vlans *vlan***

It is read along the cascade of the token: first on the token, then on
the user, then on the unit, then on the site.

The VLAN goes out with the answer of an 802.1X port authentication.

## Offline Configuration

A host may keep a copy of a token so that the user can still log in
while the realm cannot be reached — the notebook on the road. The copy
is encrypted on the host.

Where the key for it comes from depends on the token. A password or OTP
token derives it from what the user types, with the hash of
**offline_token_hash_type** and the options of **pam_otpme**(8). A
smartcard derives it on the card: the host sends a stored challenge plus
the password to the card, and the answer of the card is the key. So a
copy of a smartcard token is worth nothing without the card.

**enable_offline *token***  
Allow the hosts to keep this token.  
Not every type can: **otp_push**, **link**, **script_otp** and
**script_static** answer "Offline usage not supported by this token".
All the others can, and start with it switched off.

**disable_offline *token***  
Do not keep it any more.

**offline_expiry *token* *time***  
How long a copy is good for, counted from the last login that reached
the realm.  
**0**, the value a token starts with, means it never expires. Time units
as in **otpme**(7).

**offline_unused_expiry *token* *time***  
The same, counted from the last time the copy was used. **0** again
means never.  
Both are checked on the host, and only while nobody of that user is
logged in; what is past its time is deleted.

## Session

**enable_session_keep *token***  
Keep the login session of this token over a reboot.  
The host writes the session key into the offline copy of the token, so
the session is taken up again instead of the user logging in anew. It
needs the offline copy, see **Offline Configuration** above.  
**otp_push**, **script_otp** and **script_static** cannot do it and
answer "Session keeping not supported by this token". The other types
can, and start with it switched off.

**disable_session_keep *token***  
Do not keep the session any more.

## Auth Script

**auth_script *token* *script* **--** \[*script_options*\]**  
Set the authorization script of the token.  
The script runs at every login with this token, after the credential was
checked, and it can still refuse the login. How it gets its values is
the same as for the user scripts, see **User Scripts** in
**otpme-user**(1).

**enable_auth_script *token***  
Run that script.

**disable_auth_script *token***  
Do not run it.  
The three commands do nothing for a **script_otp** or **script_static**
token: there the script *is* the check, and there is nothing to switch
on top of it.

## Deploy

A hardware token must be deployed before it can be used. Deploy sets up
the device and creates the matching OTPme token. Name the smartcard type
with **--type** before the command:

> otpme-token --type yubikey_piv deploy john/piv

The type decides which options the command takes, so the options differ
per type. The token name is always needed and is always *user/token*.

**deploy **--list-token-types****  
List the smartcard types that can be deployed. See **Smartcard Types**
above for the token type each one creates.

## Deploy - FIDO2

**deploy \[**-d**\] \[**-r**\] \[**--no-pin**\] \[**--uv** *uv*\] *token***  
Register a FIDO2 key. The key must be plugged in and asks for a touch.

**--no-pin**  
Do not set a PIN on the key. This only matters when the key supports a
PIN but has none yet. Then deploy would ask for a new one. A PIN that is
already set is never changed.

**--uv *uv***  
User verification: **discouraged**, **preferred** or **required**.
Without this option OTPme asks the key. It takes **required** when the
key supports a PIN, **preferred** when the key does user verification or
biometrics, else **discouraged**. See also the **uv** command below.

**-r**  
Replace existing token (keep UUID).

**-d**  
Enable debug output.

## Deploy - U2F

**deploy \[**-d**\] \[**-r**\] *token***  
Register a U2F key. The key must be plugged in and asks for a touch. U2F
knows no PIN and no user verification, so **--no-pin** and **--uv** do
not exist here.

**-r**  
Replace existing token (keep UUID).

**-d**  
Enable debug output.

## Deploy - YubiKey HMAC-SHA1

**deploy \[**-d**\] \[**-r**\] \[**-n**\] \[**-s** *slot*\] *token***  
Write an HMAC-SHA1 secret to a YubiKey slot. Deploy asks for a token
password. The token secret is the card's answer to a challenge, so the
secret of the card itself never leaves it. Whatever was in the slot is
lost. Deploy asks before it writes, unless you use the global **-f**.

**-s *slot***  
Slot to use. Default is slot 2.

**-n**  
Do not write to the YubiKey. Use the secret that is already in the slot.
This works because OTPme only needs the answer to a challenge, not the
secret. Use it for a card that is already set up, or to give a second
OTPme token the same card.

**-r**  
Replace existing token (keep UUID).

**-d**  
Enable debug output.

## Deploy - YubiKey OATH HOTP

**deploy \[**-d**\] \[**-r**\] \[**-s** *slot*\] *token***  
Write an OATH HOTP secret to a YubiKey slot. Deploy asks for a token
PIN. The PIN and a server secret together make the secret on the card,
so the user types the PIN before the OTP. Whatever was in the slot is
lost. Deploy asks before it writes, unless you use the global **-f**.
Re-plug the card when deploy asks for it.

**-s *slot***  
Slot to use. Default is slot 1.

**-r**  
Replace existing token (keep UUID).

**-d**  
Enable debug output.

There is no **-n** here. The secret cannot be read back from the card,
so OTPme can only register a card it wrote itself.

## Deploy - YubiKey GPG Applet

**deploy \[**-d**\] \[**-r**\] \[**-n**\] \[**--key-len** *bits*\] \[**--backup** *file*\] \[**--restore** *file*\] *token***  
Set up the GPG applet of a YubiKey and create an **ssh** token from it.
This resets the applet, so every GPG key on the card is lost.

Deploy asks for your real name, your mail address and one token password
of at least 8 characters. That password becomes the user PIN and the
Admin PIN of the card.

Deploy creates an RSA master key and three subkeys, one per card slot:
signature, encryption and authentication. The master key stays in the
backup file, the three subkeys go to the card. The SSH public key of the
token is the authentication key.

Before the keys go to the card, deploy writes a backup of them. Default
path: */dev/shm/\<real_name\>.gpg*, with spaces replaced by underscores.
Keep that file. Without it the keys are gone when the card breaks.

Deploy refuses to start when a gpg-agent is running or when *\~/.gnupg*
exists. It needs its own GPG home directory.

**--key-len *bits***  
RSA key length of the master key and of all three subkeys. Allowed:
2048, 3072 (default) and 4096. The keys are created on the host and then
moved to the card, so the card has to accept the length. Old YubiKeys
only take 2048.

**--backup *file***  
Write the key backup to *file* instead of the default path.

**--restore *file***  
Take the keys from a backup *file* instead of creating new ones. Use
this to move a token to a new card. **--key-len** does nothing here, the
keys come from the file. Deploy then asks for the passphrase of the
backup file and for a new token password. Cannot be used together with
**--backup**.

**-n**  
Do not touch the card. Read the SSH public key from a card whose GPG
applet is already set up and only register the token in OTPme.

**-r**  
Replace existing token (keep UUID).

**-d**  
Enable debug output.

## Deploy - YubiKey PIV Applet

**deploy \[**-d**\] \[**-r**\] \[**-n**\] \[**--key-len** *bits*\] \[**--sign-algo** *algo*\] \[**--encrypt-algo** *algo*\] \[**--backup** *file*\] \[**--restore** *file*\] \[**--restore-from-server**\] \[**--backup-key-file** *file*\] \[**--add-user-key**\] *token***  
Set up the PIV applet of a YubiKey. Deploy creates two keys: a sign key
in slot 9A and an encrypt key in slot 9D. It asks for a smartcard
password of at least 8 characters.

Where the key backup goes depends on the config parameter
**private_key_backup_key** of the site or unit:

> -   Not set: deploy writes a local backup file. Default path:
>     */dev/shm/\<user\>\_\<token\>.json*. The file holds both private
>     keys as PEM in a JSON file. Both are encrypted, with the token
>     password or with a second password deploy asks for.
>
> -   Set: deploy sends the backup to the server, encrypted with that
>     public key. No local file is written and **--backup** does
>     nothing. Get the keys back with **--restore-from-server**.

**--key-len *bits***  
RSA key length. Allowed: 2048 (default), 3072 and 4096. A YubiKey needs
firmware 5.7 or newer for 3072 and 4096. Only used when the algorithm is
RSA.

**--sign-algo *algo***  
Algorithm for the sign slot 9A: **rsa** (default) or **ed25519**.
Ed25519 needs YubiKey firmware 5.7 or newer.

**--encrypt-algo *algo***  
Algorithm for the encrypt slot 9D: **rsa** (default) or **x25519**.
X25519 needs YubiKey firmware 5.7 or newer.

**--backup *file***  
Write the key backup to *file* instead of the default path.

**--restore *file***  
Take the keys from a backup *file* instead of creating new ones. Cannot
be used together with **--backup**.

**--restore-from-server**  
Take the keys from the server backup of an existing token. Needs
**--backup-key-file**. Cannot be used together with **-n**.

**--backup-key-file *file***  
Private key that decrypts the server backup. This is the key file the
client wrote when **private_key_backup_key** was set on the site or
unit.

**--add-user-key**  
Use the token keys as the user's keys. This sets the sign and the
encrypt public key of the user and makes this token the key token of the
user. See **otpme-user**(1).

**-n**  
Do not touch the card. Read both public keys from a card whose PIV
applet is already set up and only register the token in OTPme.

**-r**  
Replace existing token (keep UUID).

**-d**  
Enable debug output.

## Dynamic Groups

A dynamic group is a local group on the host, not an OTPme group. At
login pam_otpme puts the user into it for that session. See **otpme**(7)
for the whole picture.

Who logs in with this token gets these groups. You can also set dynamic
groups on a role, then every token of the role gets them.

**add_dynamic_group *token* *group***  
Add a dynamic group to the token. The name must not be an OTPme group.
Needs the ACL **add:dynamic_group**. Asks before it changes anything,
the global **-f** skips the question.

**remove_dynamic_group *token* *group***  
Remove a dynamic group from the token. Needs the ACL
**remove:dynamic_group**.

**list_dynamic_groups \[**--include-roles**\] *token***  
List the dynamic groups of the token. Needs the ACL
**view:dynamic_groups**.

**--include-roles**  
Also list the dynamic groups of the roles of the token. This is the list
a login gets, minus the groups of the host.

## Listing

A command that starts with **list\_** answers what is assigned to the
token. One that starts with **find\_** answers the other question: where
is this token used. Nothing is assigned to a token except its policies
and its dynamic groups, so almost everything here is a **find\_**.

**--return-type** picks what they print: **name** (default),
**read_oid**, **full_oid** or **uuid**. A name from another site is
printed as *site/name*.

A token reaches most of what it has through its roles. These commands
show what the token itself is assigned to. Where there is a
**--include-roles**, that is how you ask for the rest.

**find_roles \[**--return-type** *TYPE*\] \[**-r**\] *token***  
Find the roles of the token. With **-r** also the roles those roles are
in. Needs the ACL **find:roles**.

**find_groups \[**--return-type** *TYPE*\] \[**--include-roles**\] *token***  
Find the groups of the token. With **--include-roles** also the groups
the token is in through its roles. Needs the ACL **find:groups**.

**find_accessgroups \[**--return-type** *TYPE*\] \[**--include-roles**\] *token***  
Find the access groups of the token. With **--include-roles** also the
ones it reaches through its roles. Needs the ACL **find:accessgroups**.

**find_scopes \[**--return-type** *TYPE*\] \[**--include-roles**\] *token***  
Find the OIDC scopes of the token. With **--include-roles** also the
ones it reaches through its roles. Needs the ACL **find:scopes**.

**find_shares \[**--return-type** *TYPE*\] *token***  
Find the shares the token may use. The roles of the token are always
included here, there is nothing to switch. **--return-type** also takes
**path**, which is the share name with its site in front. Needs the ACL
**find:shares**.

**find_hosts \[**--return-type** *TYPE*\] *token***  
Find the hosts the token is assigned to. Only direct assignments, the
roles are not followed. Needs the ACL **find:hosts**.

**find_nodes \[**--return-type** *TYPE*\] *token***  
Find the nodes the token is assigned to. Only direct assignments, the
roles are not followed. Needs the ACL **find:nodes**.

**find_acls *token***  
Find the ACLs this token holds on other objects. Not the ACLs set on the
token, those are **list_acls**. Only an admin may run this.

## Object Changelog

Every change to the object writes an entry: who made it, when, and what
was done. A change can carry a comment of its own, through the global
option **--changelog**.

An *entry_id* is the number the listing shows in front of an entry,
counted from 0.

Only the comment of an entry can be changed or removed. What was done
and by whom stays as it is.

A command that changes something asks first; the global option **-f**
skips the question.

**changelog *token***  
Show the changelog of the token. Needs the ACL **view:changelog**.

**edit_changelog *token* *entry_id* *comment***  
Set the comment of that entry, or replace the one it has. Needs the ACL
**edit:changelog**.

**del_changelog *token* *entry_id***  
Remove the comment of that entry. The entry itself stays, and an entry
without a comment is refused. Needs the ACL **edit:changelog**.

**clear_changelog *token***  
Remove every entry of the changelog.  
This needs more than the ACL **clear:changelog**: the config parameter
**allow_changelog_clearing** has to allow it (see **otpme**(7)). It is
true by default, but where no value is found at all, clearing is
refused. OTPme asks the token you are signed in with first, then the
object.

## Policy Management

A *policy* is the name of a policy, not a path. It is looked for in the
site of the token. Which policies there are, and what each of them does,
is in **otpme-policy**(1).

Attaching and detaching ask before they change anything; the global
option **-f** skips the question.

**add_policy *token* *policy***  
Attach a policy to the token.  
A policy has a list of object types it is for; one that does not name
**token** is refused. So is a second policy of a type that allows only
one per object.  
Needs the ACL **assign:policy**.

**remove_policy *token* *policy***  
Remove a policy from the token.  
Needs the ACL **remove:policy**, and that one verbatim: a plain
**remove** does not cover it. Detaching a policy takes away what it
enforces, so it must not be cheaper than attaching one.

**list_policies \[**--return-type** *TYPE*\] \[**--policy-types** *t1,t2*\] *token***  
List the policies attached to the token. Use **--return-type** to select
the attribute returned (**name**, **read_oid**, **full_oid**, **uuid**).
Use **--policy-types** to list only policies of the given types; these
are policy types, not policy names.  
Needs the ACL **view:policies**.

## ACL Management

An ACL says what somebody may do with this token. The somebody is a role
or a token, never a user.

What the three forms *acl*, **+***acl* and **++***acl* mean, and which
ACLs exist, is under **ACLs** in **otpme**(7).

A command that changes something asks first; the global option **-f**
skips the question.

**add_acl *token* *owner_type* *owner* *acl*\[**:***value*\]**  
Give a role or a token an ACL on this token.  
*owner_type* is **role** or **token**, and *owner* the path of that role
or token. An ACL may carry a value, for example **view:token_type**.  
Needs the ACL **add:acl**.

**del_acl *token* *acl***  
Take that ACL away again.  
Here the *acl* is the whole entry, owner and all, the way **list_acls**
prints it: **role:berlin/sw-admins:set_temp_password**.  
Needs the ACL **delete:acl**.

**list_acls *token***  
Show the ACLs that lie on this token, i.e. who may do what with it.
Needs the ACL **view:acl**.

**find_acls *token***  
The other direction: the ACLs this token holds on other objects.  
Admin only. This one cannot be given away.

**enable_acl_inheritance *token***  
Let the token take the ACLs that reach it from elsewhere. It does by
default.

Two things reach it: a default ACL of the unit the token sits in, and an
ACL added to its user with **-r** (see **otpme-user**(1)). A token that
does not inherit is passed over by both.

Only default ACLs are inherited. An ordinary ACL on the unit never is.

Moving a token into another unit is the one place that asks something
else as well: an admin token gets neither the default ACLs of the new
unit nor loses those of the old one. That is the admin token of the site
and every token in the site admin role **SITE_ADMIN**.

Needs the ACL **enable:acl_inheritance**.

**disable_acl_inheritance *token***  
Stop that. Only the ACLs on the token itself count from then on.  
Needs the ACL **disable:acl_inheritance**.

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
