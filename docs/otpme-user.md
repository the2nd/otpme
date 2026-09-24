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
Create a new user account. It gets a default token, whose name and type
come from **default_token_name** and **default_token_type** (see
**otpme**(7)) unless **--default-token** or **--default-token-type**
says otherwise. **--no-default-token** creates the user without one.

**del \[**--no-trash**\] *user* \[*user* ...\]**  
Delete one or more user accounts. The user and their tokens go to the
trash, from where **otpme-trash**(1) can bring them back. **--no-trash**
deletes them right away instead.

**show \[*user*\]**  
Display user information. Without arguments, shows all users.

**list \[**-a**\] \[**--attribute** *ATTR*\] \[*regex*\]**  
List the users, and with a regex only those whose name matches it.  
You get the users you may change; **-a** adds those you may only look
at. **--attribute** shows the given attribute instead of the name.

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
Move the user into another unit. The default ACLs of the old unit go,
those of the new one come; **--keep-acls** leaves the ACLs as they are.

**touch *user***  
Re-index the object to fix potential index problems.

**auto_disable \[**-u**\] *user* *time***  
Set auto-disable time. It is either a relative time with a leading
**+**, e.g. **+30D**, or an absolute one, e.g. **"09:53 13.06.2023"**.
The units are **s**, **m**, **h**, **D**, **W**, **M** and **Y**, see
**otpme**(7). Use **-u** to disable the user if they were not used for
the given time.

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

**find_groups \[**--return-type** *TYPE*\] \[*user*\]**  
Find groups the user belongs to. Use **--return-type** to select the
attribute returned (**name**, **read_oid**, **full_oid**, **uuid**).

## Role Membership

Roles are managed from the role side; see **otpme-role**(1).

**find_roles \[**--return-type** *TYPE*\] \[*user*\]**  
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

**list_policies \[**--return-type** *TYPE*\] \[**--policy-types** *t1,t2*\] *user***  
List the policies attached to the user. Use **--return-type** to select
the attribute returned (**name**, **read_oid**, **full_oid**, **uuid**).
Use **--policy-types** to list only policies of the given types; these
are policy types, not policy names.  
Needs the ACL **view:policies**.

## User Configuration

**config \[**-d**\] \[**-a**\] *user* *parameter* \[*value*\]**  
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

**info \[**--language** *LANG*\] *user* \[*info*\]**  
Set the info text of the user, a free text that may run over several
paragraphs. Without a text OTPme opens the current one in the editor
named by **EDITOR**.  
An info text is kept per language. **--language** says which one, e.g.
**--language de**. Without it the text is stored under **info**, which
is the note of the administrator and is never shown to a user.  
How long such a text may be is **max_info_len** in **otpme**(7), which
also says who reads it.

**dump_info \[**--language** *LANG*\] *user***  
Write the info text of that language to stdout.

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

**gen_keys \[*options*\] *user***  
Generate the sign and the encrypt key pair of the user. Both are RSA by
default; **--sign-algo** and **--encrypt-algo** choose another one, see
**Key Generation Options** below.

**del_keys *user***  
Remove all four keys of the user: both private and both public ones. It
asks first, and it refuses when the user has no keys at all. Needs the
ACL **del_keys**.

**gen_csr \[**--stdin-pass**\] *user***  
Make a certificate signing request with the private key of the user and
write it to stdout. The key script does the work, so the key never
leaves where it lies.  
It stops there: OTPme does not hand the request to a CA and does not
store a certificate. What happens with the request is up to you.
**--stdin-pass** reads the key password from stdin.

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

**key_pass \[**--stdin-pass**\] *user***  
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

**import_sign_key \[**--server**\] \[**-n**\] \[**--stdin-key**\] *user* \[*private_key_file*\]**  
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

**import_encrypt_key \[**--server**\] \[**-n**\] \[**--stdin-key**\] *user* \[*private_key_file*\]**  
The same for the encrypt key, with the ACLs **edit:encrypt_private_key**
and **import_encrypt_key**. Options as for **import_sign_key**.

**dump_sign_key \[**-p**\] \[**-n**\] \[**--stdin-pass**\] *user***  
Write the sign key of the user to stdout. Without **-p** that is the
public key, base64 encoded; **-n** writes it decoded instead.  
**-p** writes the private key. In server key mode **-n** decrypts it
first, which asks the client for the key password; without **-n** you
get the stored, still encrypted form. In client key mode you get what
the client put there.  
Dumping the private key needs the ACL **dump:sign_private_key**, the
public one **dump:sign_public_key**. The user themselves needs neither.

**dump_encrypt_key \[**-p**\] \[**-n**\] \[**--stdin-pass**\] *user***  
The same for the encrypt key, with the ACLs **dump:encrypt_private_key**
and **dump:encrypt_public_key**. Options as for **dump_sign_key**.

**find_signatures \[**--return-type** *TYPE*\] \[**--object-types** *t1,t2*\] \[*user*\]**  
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
Show the changelog of the user. Needs the ACL **view:changelog**.

**edit_changelog *user* *entry_id* *comment***  
Set the comment of that entry, or replace the one it has. Needs the ACL
**edit:changelog**.

**del_changelog *user* *entry_id***  
Remove the comment of that entry. The entry itself stays, and an entry
without a comment is refused. Needs the ACL **edit:changelog**.

**clear_changelog *user***  
Remove every entry of the changelog.  
This needs more than the ACL **clear:changelog**: the config parameter
**allow_changelog_clearing** has to allow it (see **otpme**(7)). It is
true by default, but where no value is found at all, clearing is
refused. OTPme asks the token you are signed in with first, then the
object.

## ACL Management

An ACL says what somebody may do with this user. The somebody is a role
or a token, never another user.

What the three forms *acl*, **+***acl* and **++***acl* mean, and which
ACLs exist, is under **ACLs** in **otpme**(7).

A command that changes something asks first; the global option **-f**
skips the question.

A user holds no ACLs of their own, so there is no **find_acls** here.
Their tokens do; see **otpme-token**(1).

**add_acl \[**-r**\] \[**-a**\] *user* *owner_type* *owner* *acl*\[**:***value*\]**  
Give a role or a token an ACL on this user.  
*owner_type* is **role** or **token**, and *owner* the path of that role
or token. An ACL may carry a value, e.g. **edit:password**.  
**-r** adds the ACL to the tokens of the user as well. **-a** applies
the default ACLs of the user to the tokens it already has.  
Needs the ACL **add:acl**.

**del_acl \[**-r**\] \[**-a**\] *user* *acl*\[**:***value*\]**  
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
Let the user inherit the default ACLs of the unit above them. They do
not by default.

Only default ACLs are inherited. An ordinary ACL on the unit never is.

Moving a user into another unit is the one place that asks something
else as well: an admin user gets neither the default ACLs of the new
unit nor loses those of the old one. A user counts as admin when one of
their tokens is the admin token of the site or is in the site admin role
**SITE_ADMIN**.

Needs the ACL **enable:acl_inheritance**.

**disable_acl_inheritance *user***  
Stop inheriting them. Only the ACLs on the user itself count from then
on.  
Needs the ACL **disable:acl_inheritance**.

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

**show_ldif \[**-a** *attr1,attr2*\] *user***  
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

**export \[**--password** *PASS*\] *user***  
Write the whole object of the user to stdout, as JSON.  
Without **--password** it is written as it is, in clear. With one, a key
is derived from that password and the object is encrypted with it; the
salt goes into the output, so the password is all you need to read it
back.  
Reading it back in is **otpme-tool** **import**, see **otpme-tool**(1).

**remove_orphans \[**-r**\] *user***  
Remove what the user still points at although it is gone: ACLs,
policies, signatures and tokens whose object does not exist any more.  
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
Create the user from that template. It cannot be used together with
**-t**: a template is not made from a template.

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
Of **list**: show this attribute instead of the name.

## Other Options

**--keep-acls**  
Of **move**: leave the ACLs of the user alone.  
Without it a move removes the default ACLs of the old unit and applies
those of the new one. That does not happen for a user who inherits no
ACLs, for an admin user, or where you may not add and remove ACLs on the
user.

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
