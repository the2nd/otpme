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

**add** \[*options*\] *username*  
Create a new user account. It gets a default token, whose name and type
come from **default_token_name** and **default_token_type** (see
**otpme**(7)) unless **--default-token** or **--default-token-type**
says otherwise. **--no-default-token** creates the user without one.  
The secret and the PIN of the new default token, or the password it made
up, are shown only with the right ACLs on that token:
**view:initial_secret** and **view:initial_pin**. Who may add users does
not get them by that alone. To let the role **helpdesk** see them for
new users of the unit **linux/users**, add the ACLs to that unit:

    otpme-unit add_acl linux/users role helpdesk ++token:view:initial_secret
    otpme-unit add_acl linux/users role helpdesk ++token:view:initial_pin

They only count when the token is added, so the role does not see the
secret later. The ACL group **USERMANAGER** holds both, see
**otpme-aclgroup**(1). Without them, give the user a way in with a
temporary password, see **temp_password** in **otpme-token**(1). More in
**otpme-token**(1) under **add**.

**del** \[**--no-trash**\] *user* \[*user* ...\]  
Delete one or more user accounts. The user and their tokens go to the
trash, from where **otpme-trash**(1) can bring them back. **--no-trash**
deletes them right away instead.

**show** \[*user*\]  
Display user information. Without arguments, shows all users.  
With a user it shows the fields of the user and a table of its tokens. A
field you may not see shows **-**. The tokens are shown as with
**otpme-token show**: what you see of each token depends on your ACLs on
it, and a token you have no ACL on is left out.

<!-- -->

**show_oid** \[**--full**\] *user*  
Show the OID of the user: **user\|\<realm\>/\<name\>**. With **--full**
the full OID, which names the site and unit as well:
**user\|\<realm\>/\<site\>/\<unit_path\>/\<name\>**.  
Needs the ACL **view_public:object**.

**show_uuid *user***  
Show the UUID of the user.  
Needs the ACL **view_public:object**.

<!-- -->

**list** \[**-a**\] \[**-t**\] \[**--attribute** *ATTR*\] \[*pattern*\]  
List the users, and with a pattern only those whose name matches it, see
**SELECTING OBJECTS** in **otpme**(1).  
You get the users you may change; **-a** adds those you may only look
at. **-t** lists the user templates instead. Without **-a** these are
the templates you may change or have **use** on, i.e. the ones you may
give to **add --template**. **--attribute** matches the pattern against
that attribute instead of the name.

**enable** \[**--share-notify**\|**--no-share-notify**\] \[**--no-persist-mount**\] *user*  
Enable a disabled user account.

**--share-notify**  
Send notification to all online hosts on new share permissions.

**--no-share-notify**  
Do not send notification to all online hosts on new share permissions.

**--no-persist-mount**  
Do not persist new share mounts on hosts.

**disable** \[**--share-notify**\|**--no-share-notify**\] \[**--no-persist-mount**\] *user*  
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

**move** \[**--keep-acls**\] *user* *unit*  
Move the user into another unit. The default ACLs of the old unit go,
those of the new one come; **--keep-acls** leaves the ACLs as they are.

**touch *user***  
Re-index the object to fix potential index problems.

**auto_disable** \[**-u**\] *user* *time*  
Set auto-disable time. It is either a relative time with a leading
**+**, e.g. **+30D**, or an absolute one, e.g. **"09:53 13.06.2023"**.
The units are **s**, **m**, **h**, **D**, **W**, **M** and **Y**, see
**otpme**(7). A relative time counts from when it is set, and again from
when the user is enabled. **0** removes it. It is refused for a user the
realm or a site comes with, e.g. the admin; a time set on one before
does nothing. Use **-u** to disable the user once they were unused for
the given time. That takes a relative time; a user who was never used
counts from when this was set.

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

The ACL is set on two kinds of token only: the user's default token, and
the SSO token of every site that has one for this user. Those are the
tokens the user signs in with. It is not set on the user object, and not
on their other tokens. A token may be given a temporary password when it
carries the ACL itself or when the user does, so one on the user would
cover every token they have. Errors if the user has none of these
tokens.

**disable_admin_access *user***  
Disable admin access for the user: clear **allow_temp_passwords**,
revoke the **set_temp_password** ACL from the same tokens, and purge any
active temporary password from every token that still has one.

## Token Management

Tokens are managed from the token side; see **otpme-token**(1).

## Group Membership

**group *user* *group***  
Change the user's default group. (A user is added to further groups from
the group side; see **otpme-group**(1).)  
For a template, **""** takes its group away: a user made from it then
gets the group a policy or the site gives. A user that is no template
always has a group.

**find_groups** \[**--return-type** *TYPE*\] \[*user*\]  
Find groups the user belongs to. Use **--return-type** to select the
attribute returned (**name**, **read_oid**, **full_oid**, **uuid**).

## Role Membership

Roles are managed from the role side; see **otpme-role**(1).

**find_roles** \[**--return-type** *TYPE*\] \[*user*\]  
Find roles assigned to the user. Use **--return-type** to select the
attribute returned (**name**, **read_oid**, **full_oid**, **uuid**).

## Policy Management

A *policy* is the name of a policy, not a path. It is looked for in the
site of the user. Which policies there are, and what each of them does,
is in **otpme-policy**(1).

Attaching and detaching ask before they change anything; the global
option **-f** skips the question.

**add_policy *user* *policy***  
Attach a policy to the user.  
A policy has a list of object types it is for; one that does not name
**user** is refused. So is a second policy of a type that allows only
one per object.  
Needs the ACL **assign:policy**.

**remove_policy *user* *policy***  
Remove a policy from the user.  
Needs the ACL **remove:policy**, and that one verbatim: a plain
**remove** does not cover it. Detaching a policy takes away what it
enforces, so it must not be cheaper than attaching one.

**list_policies** \[**--return-type** *TYPE*\] \[**--policy-types** *t1,t2*\] *user*  
List the policies attached to the user, the disabled ones too, marked
**(disabled)**. Use **--return-type** to select the attribute returned
(**name**, **read_oid**, **full_oid**, **uuid**). Use **--policy-types**
to list only policies of the given types; these are policy types, not
policy names.  
Needs the ACL **view:policies**.

## User Configuration

**config** \[**-d**\] \[**-a**\] *user* *parameter* \[*value*\]  
Set a configuration parameter on the user. **-a** appends the value to a
parameter that holds a list.  
**-d** removes the parameter from the user, or with a value only that
one value from a list. The parameter is then looked up on the user's
unit and on the site again, so what the user gets is whatever stands
there. See **CONFIG PARAMETERS** in **otpme**(7).

**show_config *user* \[*parameter*\]**  
Show the configuration parameters set on the user, or only the given
one.

**get_config *user* *parameter***  
Show the value of one parameter, as the user sees it after the lookup on
unit and site.

**description *user* \[*description*\]**  
Set the description of the user. Without a description OTPme asks for
one and offers the current text for editing.

**info** \[**--language** *LANG*\] *user* \[*info*\]  
Set the info text of the user, a free text that may run over several
paragraphs. Without a text OTPme opens the current one in the editor
named by **EDITOR**.  
An info text is kept per language. **--language** says which one, e.g.
**--language de**. Without it the text is stored under **info**, which
is the note of the administrator and is never shown to a user.  
How long such a text may be is **max_info_len** in **otpme**(7), which
also says who reads it.

**dump_info** \[**--language** *LANG*\] *user*  
Write the info text of that language to stdout.

**show_info** *user*  
List the languages the user has a text for, one per line, with the first
line of the text. The note of the administrator comes first, as **-**.
An empty text is not listed.  
Needs the ACL **view:info**.

**language *user* *language***  
Set the user's localization language (e.g. "en", "de").

**enable_disabled_login *user***  
Allow the user to log in even if the accessgroup is disabled.

**disable_disabled_login *user***  
Undo **enable_disabled_login**.

**unblock *user* \[*accessgroup*\]**  
Unblock the user for the given accessgroup, or for all accessgroups if
none is given.

**show_sso_terms *user***  
Show the terms of use the user accepted at the SSO portals: per site of
the portal the version, when and in which language. See
**sso_confirm_terms** in **otpme**(7).  
Needs the ACL **view:sso_terms**.

**reset_sso_terms *user* \[*site*\]**  
Forget that the user accepted the terms of use of that site, or of all
sites. The portal asks again at the next deploy of an SSO token.  
Needs the ACL **delete:sso_terms**.

**enable_auto_mount *user* / **disable_auto_mount** *user***  
See **User Management** above.

**enable_autosign *user***  
Sign every object this user changes, without asking.  
It works next to the config parameter **auto_sign** (see **otpme**(7)):
one of the two is enough for the signature to happen.

**disable_autosign *user***  
Do not sign automatically any more. An object whose **auto_sign** says
otherwise is still signed.

## User Scripts

The script options after **--** say how the script gets its values:
**\[NAME\]** puts a value into the environment of the script, **%name**
makes it a command line argument, and everything else goes to the
command line as it is. Without options the script gets all values in its
environment. The values themselves are listed under **User Scripts** in
**otpme**(7).

Where the script itself is optional, leaving it out makes OTPme ask for
it, with the script the user has now and its options ready for editing.

**auth_script *user* *script* **--** \[*script_options*\]**  
Set the user's authorization script. This one needs the script; the
three below do not.

**enable_auth_script *user* / **disable_auth_script** *user***  
Enable / disable the user's authorization script.

**key_script *user* \[*script*\] **--** \[*script_options*\]**  
Set the user's key script. OTPme runs it for all work with the user's
keys: make them, sign, verify, encrypt, decrypt, make a CSR and change
the key password. It gives the command first, then the script options
set here, then the options of the call.

The default key script **key_script.sh** takes these script options:

**--yubikey-piv \[*slot*\]**  
The private keys are on a YubiKey in PIV mode. Signing and decrypting
happen on the card, always through otpme-agent; the key script never
sees the PIN.  
The agent holds the PIN login of the card, its PIV session. Logging in
with the token opens it; where there is none, the agent asks for the
PIN. It stays open for the **key_cache_time** of the user, or for
**YUBIKEY_PIV_TIMEOUT** seconds where that is set in
*\~/.otpme/otpme-agent.conf*; with neither, until the agent ends.  
While the session is open, the agent asks to confirm each use of the
card, with what it is for, e.g. the share or the password. It asks only
in a graphical session: on a console the shell reads the terminal, so
the agent uses the card without asking. **AGENT_CONFIRM_ACTIONS** in
**otpme.conf**(5) switches it off for a host.  
*slot* is the slot **gen_csr** uses when it is not told one:
**AUTHENTICATION**, **SIGNATURE**, **KEY_MANAGEMENT** or **CARD_AUTH**.
It can be left out.

**--use-agent-piv**  
Taken for settings from before, and does nothing: **--yubikey-piv**
always goes through otpme-agent.

**--yubikey-hmac *slot***  
The passphrase of the private key goes through the HMAC
challenge-response of the YubiKey in *slot* (1 or 2). Without the
YubiKey the private key does not open. Encrypted files stay with the
public key. It needs the program **ykchalresp**.

**--use-gpg *id***  
The private key is encrypted with the GPG key *id*, not with a
passphrase.

**--key-enc rsa\|**aes**\|**gpg**\|**yubikey-hmac****  
How **encrypt** protects the key of a file. **rsa** is the default: the
public key of the user, or of the user of **-u**. **aes**: a passphrase.
**gpg**: the GPG key of **--use-gpg**. **yubikey-hmac**: a passphrase
that goes through the YubiKey of **--yubikey-hmac**. With anything but
**rsa**, **encrypt -u** and **encrypt --rsa** are refused. Decrypting
follows what the file says, not this option.

**--salt-file *file***  
The SHA1 sum of *file* goes before every passphrase: that of the private
key and that of a file. Without the file nothing opens. A file that
cannot be read is an error. A file encrypted with a salt does not
decrypt itself with a passphrase: it calls **otpme-tool decrypt**.

**--no-self-decrypt**  
Encrypted files get no script. Normally a file has a script at its
start, and running the file decrypts it.

OTPme gives these options itself, for the call it makes: **-u**,
**--rsa**, **--no-rsa** and **--force-pass** (from **otpme-tool
encrypt**), **--algo** and **-b** (from **gen_keys**), **--server-key**
(key mode server), **--reason** (the text of the PIN prompt), **--api**
and **--auth-token** (API mode).

**get_key_script *user* \[**name**\|**uuid**\]**  
Show the name or UUID of the user's key script.

**agent_script *user* \[*script*\] **--** \[*script_options*\]**  
Set the user's agent script. It starts and stops the SSH agent of the
user, see **SSH Agent** in **otpme-tool**(1). PAM runs it as well:
**add_key** after a login, **unlock** when the screen is unlocked with
an SSH token.

The default agent script **agent_script.sh** starts ssh-agent and takes
these script options:

**--gpg-agent**  
Start gpg-agent with SSH support, not ssh-agent.

**--gpg-smartcard**  
Like **--gpg-agent**, for a GPG smartcard. On screen unlock the card
asks for its PIN again. Only one gpg-agent of the user can run then, so
**status** counts all of them.

**--pinentry *program***  
The pinentry program of gpg-agent. The default is **otpme-pinentry**.

**--yubikey-piv**  
**add_key** adds the key of the YubiKey PIV token to the agent. The
password of the login is taken as its PIN.

**--no-confirm**  
Only with **--yubikey-piv**. The agent uses the key without asking each
time. Without it every use of the key has to be confirmed.

**Examples.** Key script and agent script go together. For a user whose
keys are on a YubiKey in PIV mode:

<!-- -->

    otpme-user key_script alice scripts/key_script.sh -- --yubikey-piv AUTHENTICATION
    otpme-user agent_script alice scripts/agent_script.sh -- --yubikey-piv

> For a user with a GPG smartcard, e.g. a YubiKey deployed as
> **yubikey_gpg**: the private key is encrypted with the GPG key of the
> card, and gpg-agent is the SSH agent.

    otpme-user key_script alice scripts/key_script.sh -- --use-gpg alice@example.org
    otpme-user agent_script alice scripts/agent_script.sh -- --gpg-smartcard

> **otpme-user show** then lists them, e.g.

    key_script:    scripts/key_script.sh --yubikey-piv AUTHENTICATION
    agent_script:  scripts/agent_script.sh --yubikey-piv

**login_script *user* \[*script*\] **--** \[*script_options*\]**  
Set the user's login script.

**enable_login_script *user* / **disable_login_script** *user***  
Enable / disable the user's login script.

## VLAN Assignment

A user is never the object of a port authentication — a token is. So a
user has no VLAN of its own, and it cannot be made a member of one.

The way to give a person a VLAN is to put their token, or a role that
token is in, into the VLAN:

> **otpme-vlan add_token *vlan* *user***/***token***

That is the assignment that counts. A VLAN of the site answering the
RADIUS request that names the token, or a role the token is in, decides
the answer, and nothing below is asked any more (see **otpme-vlan**(1)).

Only where no such VLAN names the token does OTPme ask the **vlans**
config parameter, and only there is the value on the user of any use:

> **otpme-user config *user* vlans *vlan***

The parameter is read along the cascade of the *token*: first on the
token, then on the user, then on the unit, then on the site (see
**otpme**(7)). The value on the user is therefore what the tokens of
that user get as long as none of them carries one of its own.

## Cryptographic Keys

**gen_keys** \[*options*\] *user*  
Generate the sign and the encrypt key pair of the user. Both are RSA by
default; **--sign-algo** and **--encrypt-algo** choose another one, see
**Key Generation Options** below.

**del_keys *user***  
Remove all four keys of the user: both private and both public ones. It
asks first, and it refuses when the user has no keys at all. Needs the
ACL **del_keys**.

**gen_csr** \[*attributes*\] \[**--slot** *slot*\] \[**--stdin-pass**\] *user*  
Make a certificate signing request with the private key of the user and
write it to stdout. The key script does the work, so the key never
leaves where it lies.  
It stops there: OTPme does not hand the request to a CA and does not
store a certificate. What happens with the request is up to you.  
The subject is built from these, and an attribute you do not give is
left out:

**--cn *name***  
The common name. Without it, the name of the user.

**--country *country***  
Two letters, for example **DE**.

**--state *state***  

**--locality *locality***  

**--organization *organization***  

**--ou *unit***  

**--email *address***  

For a certificate that is to be used for S/MIME, three more. Without
them the request asks for nothing and what the certificate may be used
for is whatever the CA puts in:

**--san-email *address*\[**,***address*...\]**  
The address in the subject alternative name. That is where a mail client
looks for the address of the sender. **--email** puts it in the subject
as well, but on its own that is the old way.

**--key-usage *usage*\[**,***usage*...\]**  
What the key may do. For S/MIME: **digital_signature** to sign and
**key_encipherment** to be sent encrypted mail. Also
**content_commitment**, **data_encipherment**, **key_agreement**,
**key_cert_sign**, **crl_sign**, **encipher_only**, **decipher_only**.

**--ext-key-usage *usage*\[**,***usage*...\]**  
What the certificate is for. For S/MIME: **email_protection**. Also
**client_auth**, **server_auth**, **code_signing**, **smartcard_logon**,
**time_stamping**, **ocsp_signing**.

Whether the signed certificate carries all of it is up to the CA: a
request asks, it does not decide.

A user whose private key is on a YubiKey in PIV mode gets a request
signed by the card, because the key does not come off it. otpme-agent
does it, and asks for the PIN or to confirm, see **--yubikey-piv** under
**key_script**. The key is the one the key script is set to
(**--yubikey-piv**), and **--slot** asks for another one. Where neither
says a slot, it is **AUTHENTICATION**, the same one signing uses.

S/MIME needs two certificates, one for each key of the user. The sign
key lies in slot **AUTHENTICATION**, the encrypt key in slot
**KEY_MANAGEMENT**. So there are two requests. With RSA keys they read:

>     $ otpme-user gen_csr --slot AUTHENTICATION \
>         --email alice@example.org --san-email alice@example.org \
>         --key-usage digital_signature \
>         --ext-key-usage email_protection alice > alice-sign.csr
>
>     $ otpme-user gen_csr --slot KEY_MANAGEMENT \
>         --email alice@example.org --san-email alice@example.org \
>         --key-usage key_encipherment \
>         --ext-key-usage email_protection alice > alice-encrypt.csr

> Hand both to your CA. Each signed certificate then has to go back into
> the slot its key sits in:

>     $ otpme-yk-piv --import-cert --slot AUTHENTICATION < alice-sign.crt
>     $ otpme-yk-piv --import-cert --slot KEY_MANAGEMENT < alice-encrypt.crt

> A PKCS#11 module shows the key of a slot only together with the
> certificate that sits in it, so that is what a mail client or a
> browser needs. Writing a slot asks for the management key, not for the
> PIN. A card that was deployed keeps that key on itself, and then the
> PIN reads it out.
>
> With 25519 keys the second request does not work. Ed25519 only signs,
> X25519 only does key agreement, and a request is signed by the very
> key it is for. An X25519 key cannot do that (RFC 8410). Two things
> follow. First, the encrypt key needs **--key-usage key_agreement**,
> not **key_encipherment**: that bit is the RSA one. Second, there is no
> request for it at all. The CA has to issue the certificate from the
> public key alone:

>     $ otpme-yk-piv --public-key-out --slot KEY_MANAGEMENT > alice-encrypt.pub

> Not every CA does that, and whether a mail client reads X25519 in
> S/MIME at all (RFC 8418) is another question. Use RSA where you are
> not sure.
>
> **--stdin-pass** reads the key password from stdin.  
> A request without any of the S/MIME parts:

>     $ otpme-user gen_csr --organization 'Example Ltd' --country DE --email alice@example.org alice

**key_mode *user* *mode***  
Where the private keys of the user are kept.

**client**  
They stay on the client, which hands the server a blob it cannot read.

**server**  
They lie on the server, wrapped in an AES key that the client encrypts
with the key password of the user. Reading one means asking the client
to unwrap it.

**get_key_mode *user***  
Show the key mode of the user. A user who never had one set is
**client**.

**get_sign_key_type *user***  
Show what kind of sign key the user has: **rsa** or **ed25519**.

**get_enc_key_type *user***  
Show what kind of encrypt key the user has: **rsa** or **x25519**.

**key_cache_time *user* *time***  
Set how long otpme-agent may cache the users private key, e.g. how long
it keeps the yubikey PIV handler open after the PIN was entered. Accepts
a plain number of seconds or a time string such as *5m*. The default *0*
means no timeout, the key stays cached as long as the agent runs. The
agent gets the value with the login session, so a change takes effect on
the next login.

**enable_key_caching *user***  
Let the hosts hold the private keys of the user. Needs key mode
**client** and refuses otherwise.

The login then sends the keys to the host the user logs in on. They
travel as they are stored: wrapped with the key password of the user. A
host that holds one can do no more with it than it could before, because
without that password it is of no use. The host writes it to its offline
tokens and hands it to otpme-agent.

Two things follow. The key script does not ask the servers for the key
on every call, and it asks for the key password once per session instead
of once per signature: it unwraps the key and leaves the result with the
agent for **key_cache_time**. And the user can sign without the servers,
which is what an offline login needs.

It also lets the agent sign the SOTP for a user whose login token does
not own the keys, see **sotp_signing** in **otpme-accessgroup**(1).
Without a key it holds, the agent has nothing to sign with.

Off by default. Which hosts hold a copy of a private key is not
something to decide by accident. In key mode **server** nothing is ever
sent: there the key that wraps the private key is on the server too, and
a host that got both would have the key itself.

**otpme-user show** says whether it is on, as **key-caching**. It says
**N/A** where the key mode is not **client**, because there it cannot be
turned on at all.

**disable_key_caching *user***  
Stop sending the private keys of the user to the hosts.

This is about the next login. What a host has already got stays in its
offline tokens until the user logs in there again, and in its agent
until the user logs out. A key that must be gone everywhere has to be
replaced, see **key_pass** and **gen_keys**.

**key_pass** \[**--stdin-pass**\] *user*  
Change the password of the private keys of the user. **--stdin-pass**
reads it from stdin.

**sign_private_key *user* *private_key***  
Set the sign private key of the user, as the client keeps it. An empty
value removes the key.  
Only the user themselves may do this; there is no ACL that lets somebody
else.

**encrypt_private_key *user* *private_key***  
The same for the encrypt private key.

**sign_public_key *user* *public_key***  
Set the sign public key of the user.  
The user themselves needs no permission for it. Anybody else needs the
ACL **edit:sign_public_key**.

**encrypt_public_key *user* *public_key***  
The same for the encrypt public key, with the ACL
**edit:encrypt_public_key**.

**import_sign_key** \[**--server**\] \[**-n**\] \[**--stdin-key**\] *user* \[*private_key_file*\]  
Take a private key the user already has and make it their sign key. The
key comes from a file, or from stdin with **--stdin-key**.  
It only works in server key mode. In client key mode the key belongs to
the client, and importing one is refused.  
Without **--server** the key script on the client encrypts the key with
the key password of the user, and only the encrypted private key and the
public key are sent. With **--server** the key itself is sent and the
server wraps it, the way **gen_keys** does. Either way the key ends up
on the server.  
The user themselves needs no permission for it. Anybody else needs the
ACL **edit:sign_private_key**, plus **import_sign_key**.

**import_encrypt_key** \[**--server**\] \[**-n**\] \[**--stdin-key**\] *user* \[*private_key_file*\]  
The same for the encrypt key, with the ACLs **edit:encrypt_private_key**
and **import_encrypt_key**. Options as for **import_sign_key**.

**dump_sign_key** \[**-p**\] \[**-n**\] \[**--stdin-pass**\] *user*  
Write the sign key of the user to stdout. Without **-p** that is the
public key, base64 encoded; **-n** writes it decoded instead.  
**-p** writes the private key. In server key mode **-n** decrypts it
first, which asks the client for the key password; without **-n** you
get the stored, still encrypted form. In client key mode you get what
the client put there.  
Dumping the private key needs the ACL **dump:sign_private_key**, the
user themselves does not need it. The public key needs no ACL.

**dump_encrypt_key** \[**-p**\] \[**-n**\] \[**--stdin-pass**\] *user*  
The same for the encrypt key, with the ACL **dump:encrypt_private_key**.
Options as for **dump_sign_key**.

**find_signatures** \[**--return-type** *TYPE*\] \[**--object-types** *t1,t2*\] \[*user*\]  
Find the objects the user has signed. Signing writes the signer into the
index, so the answer comes from the index. No object is read.  
What is found can be of any type, so the default answer names the type:
**token\|realm/site/user/name**. Use **--return-type** to select another
attribute (**name**, **rel_path**, **read_oid**, **full_oid**,
**uuid**). Use **--object-types** to search the given types only.  
Only objects you may see are listed. Needs the ACL **find:signatures**.

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

**changelog *user***  
Show the changelog of the user, one entry per line: its *entry_id*, the
time, who made the change and what was done, then a detail in round
brackets and the comment in square brackets where there are any. Needs
the ACL **view:changelog**.

**edit_changelog *user* *entry_id* *comment***  
Set the comment of that entry, or replace the one it has. That writes an
entry of its own. Needs the ACL **edit:changelog**.

**del_changelog *user* *entry_id***  
Remove the comment of that entry. The entry itself stays, and an entry
without a comment is refused. That writes an entry of its own. Needs the
ACL **edit:changelog**.

**clear_changelog *user***  
Remove every entry of the changelog. Afterwards it holds one entry: that
it was cleared.  
This needs more than the ACL **clear:changelog**: the config parameter
**allow_changelog_clearing** has to allow it (see **otpme**(7)). It is
true by default, but where no value is found at all, clearing is
refused. A value set on the token you are signed in with counts first.
Without one, the value of the object counts, read along its cascade.

## ACL Management

An ACL says what somebody may do with this user. The somebody is a role
or a token, never another user.

What the three forms *acl*, **+*acl*** and **++*acl*** mean, and which
ACLs exist, is under **ACLs** in **otpme**(7).

A command that changes something asks first; the global option **-f**
skips the question.

A user holds no ACLs of their own, so there is no **find_acls** here.
Their tokens do; see **otpme-token**(1).

**add_acl** \[**-r**\] \[**-a**\] *user* *owner_type* *owner* *acl*\[:*value*\]\[,*acl*\[:*value*\]\]  
Give a role or a token one or more ACLs on this user.  
*owner_type* is **role** or **token**. *owner* names it the way
**list_acls** prints it: a role as *site/name*, or by its name alone on
its own site; a token as *user/token*. An ACL can carry a value, for
example **edit:password**. To give several ACLs at once, separate them
with commas: **edit:password,view:status**.  
**-r** adds the ACL to the tokens of the user as well. **-a** applies
the default ACLs of the user to the tokens it already has.  
Needs the ACL **add:acl**.

**del_acl** \[**-r**\] \[**-a**\] *user* *acl*\[**:*value***\]  
Take that ACL away again. **-r** removes it from the tokens of the user
as well, **-a** removes the default ACLs from the tokens it already
has.  
Here the *acl* is the whole entry, owner and all, the way **list_acls**
prints it: **role:berlin/sw-admins:edit**.  
Needs the ACL **delete:acl**.

**list_acls *user***  
Show the ACLs that lie on this user, i.e. who may do what with them.
Needs the ACL **view:acl**.

**enable_acl_inheritance *user***  
Let a move of the user swap their default ACLs: what the old unit handed
down is taken away, and what the new unit hands down is given. They do
not by default; a move then leaves the ACLs of the user as they are.

Only a move asks this. A new user gets the default ACLs of their unit,
and **add_acl -a** or **-r** on a unit reach them either way. A move
with **--keep-acls** leaves their ACLs alone all the same, and so does a
move of an admin user. A user counts as admin when one of their tokens
is the admin token of the site or is in the site admin role
**SITE_ADMIN**.

A move by somebody who does not hold **add:acl** and **delete:acl** on
the user leaves their ACLs alone as well, and says so. Otherwise moving
an object into a unit would be a way of handing yourself the default
ACLs of that unit.

Needs the ACL **enable:acl_inheritance**.

**disable_acl_inheritance *user***  
A move leaves the ACLs of the user as they are again.  
Needs the ACL **disable:acl_inheritance**.

## LDAP Integration

**add_attribute** \[**-i** *position*\] *user* *attribute*=\[*value*\]  
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

**show_ldif** \[**-a** *attr1,attr2*\] *user*  
Show the user as LDIF, the way LDAP hands them out. **-a** shows only
the attributes you name.

## Extension Management

An extension brings LDAP object classes and the attributes that go with
them to the user. Without one there is nothing to set with
**add_attribute** and nothing for LDAP to answer with.

A new user gets **base** and **posix**. **posix** is where
**uidNumber**, **gidNumber**, **homeDirectory** and **loginShell** come
from, the attributes a unix system asks for.

**add_extension *user* *extension***  
Add an extension to the user.

**remove_extension *user* *extension***  
Remove an extension from the user, with the attributes it brought.

## User Photo

**photo *user* *image_path***  
Set the user's photo (JPEG). A photo of another size than
**user_photo_dimensions** (see **otpme**(7)) is resized to it after
asking; **-f** resizes without asking.

**dump_photo *user***  
Dump the user's photo as base64 to stdout.

**del_photo *user***  
Remove the user's photo.

## Export and Cleanup

**export** \[**--password** *PASS*\] *user*  
Write the whole object of the user to stdout, as JSON.  
Without **--password** it is written as it is, in clear. With one, a key
is derived from that password and the object is encrypted with it; the
salt goes into the output, so the password is all you need to read it
back.  
Reading it back in is **otpme-tool** **import**, see **otpme-tool**(1).

**remove_orphans** \[**-r**\] *user*  
Remove what the user still points at although it is gone: ACLs,
policies, signatures and tokens whose object does not exist any more.
Config parameters set on the user that keep other objects lose the ones
that are gone, e.g. a deleted VLAN in **vlans** or a deleted role in
**admin_access_role**, the way **config -d** does.  
It shows everything it found and asks once. **-r** does the same for the
tokens of the user.

# OPTIONS

## User Creation Options

These are the options of **add**.

Groups and roles hold tokens, not users, so the options below put the
*default token* of the new user into them. You need the ACL
**add:token** on each group and role.

**--group *GROUP***  
The default group of the user. Without it the group of the template is
used, or else the group a policy gives, or else the default group of the
installation.

**--groups *GROUP1,GROUP2***  
Put the default token into these groups as well.

**--role *ROLE***  
Put the default token into this role.  
It also switches off the **defaultroles** policy for this user, so the
user gets this role and no other.

**--roles *ROLE1,ROLE2***  
Put the default token into these roles as well. This one leaves the
**defaultroles** policy alone.

**--password *PASS***  
The password of the default token. It only works when that token is a
password token; any other type is refused.

**--weak-password**  
Accept a password even if the password policy would reject it. Needs the
**force_password** ACL on the target unit.

**--no-default-token**  
Do not create a default token for the user.

**--default-token *NAME***  
Take a token that already lies in the **TOKENSTORE** and make it the
default token of the new user. *NAME* is its name there.  
It says nothing about the name of a *new* token: that comes from
**default_token_name**, see **otpme**(7). Giving this option also means
the user gets a default token, whatever **add_default_token** says.

**--default-token-type *TYPE***  
The type of the default token. Without it the type of
**default_token_type** is used, see **otpme**(7).

**--no-qrcode**  
Do not generate default token QR code (TOTP/HOTP only).

**--mode *MODE***  
Mode for the default token (TOTP/HOTP only). See **otpme-token**(1) for
the difference between **mode1** and **mode2**.

**-t**  
Make the new user a template, i.e. an object to create other users from.
A template gets no default token.

**--template *NAME***  
Create the user from that template. Needs **use** on the template. The
user then gets the group of the template without
**add:default_group_user** on the group. It cannot be used together with
**-t**: a template is not made from a template. Without it, the user is
created from the template an **objecttemplates** policy of the unit
names, if there is one (see **otpme-policy**(1)).

**--no-template**  
Create the user without a template, also where an **objecttemplates**
policy names one. It cannot be used together with **--template**.

**--attributes *ATTR1=VAL1,ATTR2=VAL2***  
Give the new user these LDAP attributes right away, instead of setting
them with **add_attribute** afterwards.

## Key Generation Options

**--sign-algo *ALGO***  
The algorithm of the sign key: **rsa** (the default) or **ed25519**.

**--encrypt-algo *ALGO***  
The algorithm of the encrypt key: **rsa** (the default) or **x25519**.

**-b *BITS***  
The key length in bits. It only means something for RSA.  
Without it the user's **user_key_len** is used, see **otpme**(7).

**--server**  
Generate the key pairs on the server.

**-n**  
Do not encrypt the private key on the server.

**--stdin-pass**  
Read the passphrase from stdin.

## Key Import Options

These are the options of **import_sign_key** and **import_encrypt_key**.

**--stdin-key**  
Read the private key from stdin instead of from a file.

**--server**  
Send the key to the server and let it wrap the key. Without this option
the key script on the client encrypts it first, and the key itself never
goes over the wire.

**-n**  
Store the private key unencrypted. Only together with **--server**: the
client refuses to hand out an unencrypted key.

## Display Options

These are the options of **show**, except **--attribute**, which belongs
to **list**.

**-a**  
Show every user you may look at.  
Without it you only get the users you may change, i.e. the ones you hold
a write ACL on. An admin sees every user either way.

**-t**  
Show the user templates as well.

**-z *N***  
Show at most this many users. Without it you get 10; a search that has
no number of its own stops at 1024.

**--fields *FIELD1,FIELD2***  
Show only these columns.

**--policy-limit *N***  
Show at most this many policies per user.

**--limit *N***  
Show at most this many items of every other list of a user, e.g. its
tokens or groups.

**--sort-by *FIELD***  
Sort the output by that column.

**--reverse**  
Turn the order of the output around.

**--raw**  
Leave out the headers and the borders of the table.

**--csv**  
Write the table as CSV.

**--csv-sep *SEP***  
The character between two CSV fields.

**--attribute *ATTR***  
Of **list**: match the pattern against this attribute instead of the
name, as in **list --attribute enabled True**.

## Other Options

**--keep-acls**  
Of **move**: leave the ACLs of the user alone.  
Without it a move removes the default ACLs of the old unit and applies
those of the new one, if ACL inheritance is on for the user, see
**enable_acl_inheritance**. It is off by default. That does not happen
for an admin user either, or where you may not add and remove ACLs on
the user.

**--password *PASS***  
Of **export**: the password the exported object is encrypted with. With
**add** the same option means something else, see **User Creation
Options** above.

The options that work with every command — **-f**, **--changelog** and
the rest — are in **otpme**(1).

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

**otpme-user add --role SITE_ADMIN dave**  
Create dave and put his default token into the role **SITE_ADMIN**,
which is what makes him an admin of this site

**otpme-user add --group marketing --roles employee,marketing eve**  
Create eve with **marketing** as her default group, and put her default
token into the roles **employee** and **marketing**

## Managing Tokens

**otpme-token --type totp add alice/totp**  
Give alice a second token (tokens are managed with **otpme-token**(1))

**otpme-token list alice/\***  
List the tokens alice has

**otpme-token show alice/\***  
Show them with their details

**otpme-token del alice/totp**  
Delete that token again

## Managing Groups and Roles

**otpme-user group alice marketing**  
Change alice's default group to **marketing**

**otpme-group add_token marketing alice/login**  
Put one of alice's tokens into the group **marketing** (a group holds
tokens, not users, see **otpme-group**(1))

**otpme-role add_token employee alice/login**  
Put that token into the role **employee** as well (managed from the role
side, see **otpme-role**(1))

**otpme-user find_groups alice**  
Show the groups alice is in

**otpme-user find_roles alice**  
Show the roles alice is in

## VLAN Assignment

**otpme-user config alice vlans guests**  
Set the VLAN her tokens use where no VLAN names them

**otpme-vlan add_token guests alice/totp**  
Put one of her tokens into a VLAN, which wins over the parameter above

## Applying Policies

**otpme-user add_policy alice password_strength**  
Apply the password policy OTPme ships with to alice

**otpme-user add_policy alice workhours_login**  
Let alice sign in on workdays between 6 and 18 only, with the login
times policy OTPme ships with

**otpme-user add_policy alice weekend_login**  
The same for the weekend, see **otpme-policy**(1)

**otpme-user list_policies alice**  
Show all policies applied to alice

## Key Management

**otpme-user gen_keys alice**  
Generate the sign and encrypt keys of alice, RSA with **user_key_len**
bits

**otpme-user gen_keys -b 4096 bob**  
Generate them for bob with 4096 bits instead

**otpme-user gen_keys --sign-algo ed25519 --encrypt-algo x25519 carol**  
Generate them for carol on the 25519 curves, where the length is fixed

**otpme-user key_pass alice**  
Change the password of alice's private keys

**otpme-user enable_key_caching alice**  
Let the hosts alice logs in on hold her private keys, so the key script
asks her for the password once per session and works without the servers

**otpme-user key_cache_time alice 5m**  
Have otpme-agent drop the unwrapped key five minutes after it was last
needed

**otpme-user disable_key_caching alice**  
Send them no more, from her next login on

**otpme-user dump_sign_key alice**  
Write alice's sign public key to stdout

**otpme-user find_signatures alice**  
Show every object alice has signed

**otpme-user find_signatures --object-types script alice**  
Show only the scripts she signed

## Managing User Status

**otpme-user disable alice**  
Temporarily disable alice's account

**otpme-user enable alice**  
Re-enable alice's account

**otpme-user rename alice alice_temp**  
Rename user alice to alice_temp

**otpme-user move alice users/marketing**  
Move alice into another unit, here a sub-unit of the **users** unit new
users land in

## Querying Users

**otpme-user show alice**  
Show detailed information about alice

**otpme-user list**  
List the users you may change

**otpme-user list -a**  
List every user you may look at as well

**otpme-user list "^admin.\*"**  
List the users whose name starts with **admin** (quote it, or the shell
takes the **\***)

**otpme-user show --fields name,uid,groups**  
Show only these columns

**otpme-user show_config alice**  
Show the config parameters set on alice

**otpme-tool search attribute=config value="backup_enabled"**  
Show every object that has **backup_enabled** set, whatever the value
is. A parameter is only listed where somebody set it, not where it is
inherited, so this is the way to find the places a value comes from.

## Using Templates

**otpme-user add -t developer_template**  
Create a user template for developers

**otpme-user add --template developer_template bob**  
Create bob using the developer template

**otpme-user add_acl developer_template role helpdesk use**  
Let the role **helpdesk** create users from the developer template. They
get its group, also where the role may not put users into that group
itself.

# AUTH ON ACTION HOOKS

An auth on action policy can ask for a login again before these actions.
See **Auth On Action Policy** in **otpme-policy**(1). A user has the
hooks every object type has, and these; a command of another name is in
brackets:

> add_photo (photo), add_token, change_agent_script (agent_script),
> change_auth_script (auth_script), change_encrypt_private_key
> (encrypt_private_key), change_encrypt_public_key (encrypt_public_key),
> change_group (group), change_key_cache_time (key_cache_time),
> change_key_pass (key_pass), change_key_script (key_script),
> change_login_script (login_script), change_sign_private_key
> (sign_private_key), change_sign_public_key (sign_public_key), decrypt,
> del_keys, del_photo, del_token, deploy_token, disable_admin_access,
> disable_auth_script, disable_auto_mount, disable_autosign,
> disable_disabled_login, disable_key_caching, disable_login_script,
> dump_photo, enable_admin_access, enable_auth_script,
> enable_auto_mount, enable_autosign, enable_disabled_login,
> enable_key_caching, enable_login_script, encrypt, gen_keys, move,
> pre_add_token, reset_sso_terms, set_config_parameter (config),
> show_sso_terms, sign, unblock, verify.

# SEE ALSO

**otpme**(1), **otpme**(7), **otpme-token**(1), **otpme-group**(1),
**otpme-role**(1), **otpme-policy**(1), **otpme-script**(1),
**otpme-vlan**(1), **otpme-unit**(1), **otpme-trash**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2026 the2nd. License: GPLv3
