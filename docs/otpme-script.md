# NAME

otpme-script - manage scripts: what OTPme runs at a login, for a token,
a share, a backup or a node vote

# SYNOPSIS

**otpme-script** *command* \[*options*\] \[*script*\]

# DESCRIPTION

**otpme-script** adds, changes, signs and deletes scripts. A script is a
file, most often a shell script, that is kept in the realm. It does
nothing by itself: an object names it, and OTPme runs it at a given
point.

> -   A user: the login script at a login, the key script and the agent
>     script for the keys of the user, the auth script when a login is
>     checked, see **otpme-user**(1).
>
> -   A token: the auth script, the push script of an **otp_push**
>     token, the script of a **script_otp** or **script_static** token,
>     see **otpme-token**(1).
>
> -   A share: the add script and the mount script, see
>     **otpme-share**(1).
>
> -   A node: the vote script, see **otpme-node**(1).
>
> -   A backup: the **backup_script**, before and after it, see
>     **otpme**(7).

A site comes with a script for most of these, in the unit **scripts**;
they cannot be deleted, renamed or moved. The key script and the agent
script do real work; the others do nothing until you change them.

The scripts are kept on the nodes. A host fetches a script from a node
when it runs one; the scripts of a user come with the login.

A script can be signed. A host or node that has signers of a kind, e.g.
**login_script**, runs a script of that kind only with a valid signature
of one of them, see **Signature Management** and **add_signer** in
**otpme-tool**(1). Without signers of that kind, it runs the script
unsigned.

# COMMANDS

## Script Management

A script has no status: there is no **enable** or **disable**. Nothing
that runs a script would ask for it. To stop a script from running, take
it away from what runs it, or delete it.

**add** \[**-r**\] \[**--sign**\] *script* *file*  
Add a script with the content of *file*, a file on your host. With a
path, e.g. **linux/login.sh**, it goes into that unit; else into the
unit a **defaultunits** policy names, see **otpme-policy**(1), or into
**scripts**. The name is unique in its unit, and is taken in lower case.
It may be **max_script_name_len** long (64 by default).  
Needs **add:script** on the unit.

**-r**  
Replace the content of the script, if it is there; the UUID, the ACLs
and the signatures stay. The signatures no longer match the new content:
sign it again, see **resign**. A script that is not there yet is added.
Needs **edit:script** on the script, or **add:script** on the unit for a
new one.

**--sign**  
Sign the script right away: your signatures of it are made again, with
their tags; without one you get a new one with the default tags. The
signatures of others stay as they are. With **enable_autosign** on your
user, see **otpme-user**(1), or the config parameter **auto_sign**, this
happens without **--sign**.

**del** \[**--no-trash**\] *script*  
Delete the script. It goes to the trash, see **otpme-trash**(1);
**--no-trash** deletes it right away.  
The scripts a site comes with cannot be deleted. They are in the unit
**scripts**: **agent_script.sh**, **auth_script.sh**, **key_script.sh**,
**login_script.sh**, **add_share.sh**, **mount_share.sh**,
**push_script.sh**, **backup_script.sh** and **node_vote_script.sh**.  
Needs **delete:object** on the script or **delete:script** on the unit.

**show** \[**-a**\] \[**-z** *N*\] \[**--fields** *F1,F2*\] \[**--limit** *N*\] \[**--policy-limit** *N*\] \[**--sort-by** *field*\] \[**--reverse**\] \[**--raw**\] \[**--csv**\] \[**--csv-sep** *sep*\] \[*script*\]  
Without a script: a table of all of them, with their signatures,
policies, ACL inheritance and description. A signature says who made it,
its tags, and **OK** or **FAIL**: whether it matches the content.

**-a**  
Also the scripts you may only look at, not just the ones you may change.

**-z *N***  
How many scripts to print.

**--fields *F1,F2***  
Print these columns and no others, in the order they are named. A name
with a **+** in front is added to the columns that are shown anyway, and
one with a **-** is left out of them.

**--limit *N*, **--policy-limit** *N***  
How many policies to print per script.

**--sort-by *field*, **--reverse****  
Which column to sort by, and the other way round.

**--raw, **--csv**, **--csv-sep** *sep***  
**--raw** leaves the header and the borders out, **--csv** prints one
row per line with **;** between the columns, and **--csv-sep** uses
another separator.

A column you may not see says **-**. With a script named, this prints
the object itself instead of a table row, one value per line. It shows
the MD5 sum of the content (**SCRIPT_MD5**), to those with
**view:script** or **edit:script**, but not the content; that is
**dump**. **show** ***script*$** prints that one script as a table row.
A name that is no script is a pattern with **\***, not a regex, see
**SELECTING OBJECTS** in **otpme**(1).

**show_oid** \[**--full**\] *script*  
Show the OID of the script:
**script\|\<realm\>/\<site\>/\<unit_path\>/\<name\>**. **--full** is
accepted and shows the same.  
Needs the ACL **view_public:object**.

**show_uuid *script***  
Show the UUID of the script.  
Needs the ACL **view_public:object**.

**list** \[**-a**\] \[**--attribute** *attribute*\] \[*pattern*\]  
List the scripts as *unit/name*, and with a pattern only those that
match it, e.g. **"scripts/\*"**. You get the scripts you may change;
**-a** adds those you may only look at. **--attribute** matches the
pattern against that attribute instead, e.g. **name**.

**rename *script* *new_name***  
Rename the script. The new name must not be in use in its unit. The
scripts a site comes with cannot be renamed.  
Needs **rename:object**.

**copy *script* *destination***  
Copy the content of the script to *destination*. A name alone is in the
unit of the script; with a path, e.g. **linux/login.sh**, in that unit.
Only within the site. A script that is there is replaced, after you
confirm it; else it is added. The signatures stay with the script: sign
the copy, see **sign**. A script that is replaced keeps its own
signatures, and they no longer match.  
Needs **view:script** or **dump** on the script, and **edit:script** on
the destination or **add:script** on the unit for a new one.

**move** \[**--keep-acls**\] *script* *unit*  
Move the script into another unit of the site. The script keeps its
ACLs; where ACL inheritance is on for it (off for scripts by default,
see **enable_acl_inheritance**), the default ACLs of the old unit are
taken away and those of the new one given. **--keep-acls** keeps all
ACLs as they are.  
The scripts a site comes with cannot be moved.  
Needs **move** on the script and **add:script** on the unit.

**touch *script***  
Write the index entries of the script again.  
Needs **touch**.

## Script Operations

Here, as everywhere but in **add**, a script is named by its path
*unit/name*, e.g. **scripts/login.sh**.

**dump *script***  
Print the content of the script. A script without content gives an
error.  
Needs **view:script** or **dump** on the script.

**edit** \[**--sign**\] *script*  
Open the script in your editor, **$EDITOR** or else **vim**. When you
close the editor, the new content is saved, like with **add -r**. If
nothing changed, nothing is saved. The file you edit is in
*\~/.otpme/edit/*; if saving fails, it is kept and its path is shown.  
Needs **view:script** or **dump**, and **edit:script** on the script.

**--sign**  
Sign the script after saving, like **add --sign**.

## Signature Management

A signature says that a user vouches for the content of the script. It
is made with the sign key of the user you are logged in as, by their key
script, see **otpme-user**(1). You are shown what is signed and asked
first, unless **-f** is given.

A signature has tags: **realm:**, **site:** and **script:** with the
UUIDs of the realm, the site and this script, and the tags you add with
**--tags**. A user has one signature for each set of tags.

A host runs a script only if a signer of the script type there accepts
one of its signatures, see **add_signer** in **otpme-tool**(1). A signer
can ask for tags. On a host without such a signer the script runs
unchecked.

**sign** \[**--stdin-pass**\] \[**--tags** *tag1,tag2*\] *script*  
Sign the script. If you already have a valid signature with these tags,
it is replaced only with **-f**.  
Needs **add:signature**, and **view:script** or **dump**, on the script.

**--stdin-pass**  
Read the passphrase of your private key from stdin.

**--tags *tag1,tag2***  
Add these tags to the signature. An OID, *type*:*name*, e.g.
**group:admins**, or *type*:*site*/*name*, e.g. **role:munich/admins**,
stands for that object. *type*:*name* means the object of this site; if
there is none, the one of that name in the realm. A name that is in more
than one other site needs the site, e.g. **role:munich/REALM_USER**:
every site has a role of that name. A tag for an object that does not
exist is refused. Anything else is taken as it is, for example
**sometag** or **sometag=value**. A signer of a host asks for tags
written the same way, with **add_signer --tag**. **verify_sign**,
**get_sign** and **del_sign** take tags like this too.

**resign** \[**--stdin-pass**\] *script*  
Make all your signatures of the script again, with their tags, for the
content as it is now: after **add -r** or **edit**. The signatures of
others stay as they are. **--stdin-pass** as with **sign**; the
passphrase is read once for all of them.  
Needs what **sign** needs.

**verify_sign** \[**--user** *username*\] \[**--tags** *tag1,tag2*\] *script*  
Check the signatures of the script against the content and the public
sign key of their user. It shows one line for each signature, and
succeeds if at least one of them is valid. With **--user** only the
signatures of that user, with **--tags** only those that have these tags
(and maybe more).  
Needs **verify:signature**, **view:signatures** or **view:script** on
the script.

**get_sign** \[**--user** *username*\] \[**--tags** *tag1,tag2*\] *script*  
Show the signatures, one per line as *user_uuid*:*signature*. With
**--user** only those of that user, with **--tags** only the one with
exactly these tags (and the default ones).  
Needs no ACL: a host fetches the signatures to check a script.

**del_sign** \[**--user** *username*\] \[**--tags** *tag1,tag2*\] *script*  
Delete your signature with exactly these tags (and the default ones),
after you confirm it; with **--user** that of another user. The
signature is revoked as well.  
Needs **delete:signature** on the script.

## Policy Management

A *policy* is the name of a policy, not a path. It is looked for in the
site of the script. Which policies there are, and what each of them
does, is in **otpme-policy**(1).

One policy type fits a script: **authonaction**, see **AUTH ON ACTION
HOOKS**.

Attaching and detaching ask before they change anything; the global
option **-f** skips the question.

**add_policy *script* *policy***  
Attach a policy to the script.  
A policy has a list of object types it is for; one that does not name
**script** is refused. So is a second policy of a type that allows only
one per object, even when the first one is disabled, and a policy the
script already has.  
Needs the ACL **assign:policy**.

**remove_policy *script* *policy***  
Remove a policy from the script.  
Needs the ACL **remove:policy**, and that one verbatim: a plain
**remove** does not cover it. Detaching a policy takes away what it
enforces, so it must not be cheaper than attaching one.

**list_policies** \[**--return-type** *TYPE*\] \[**--policy-types** *t1,t2*\] *script*  
List the policies attached to the script, the disabled ones too, marked
**(disabled)**. Use **--return-type** to select the attribute returned
(**name**, **read_oid**, **full_oid**, **uuid**); without it the names.
Only the names are marked. Use **--policy-types** to list only policies
of the given types; these are policy types, not policy names.  
Needs the ACL **view:policies**.

## ACL Management

An ACL says what somebody may do with this script. The somebody is a
role or a token, never a user.

What the three forms **acl**, **+acl** and **++acl** mean is under
**ACLs** in **otpme**(7). Tab completion after **add_acl** offers the
ACLs a script knows. A script has no default ACLs, **+acl** and
**++acl**: nothing lies in a script that could get them.

Besides the ACLs every object has, these matter for a script:

> **dump**, **view:script**  
> Read the content: **dump**, **edit**, **copy** and **sign** need one
> of them.
>
> **edit:script**  
> Change the content: **add -r**, **edit**, and **copy** onto this
> script.
>
> **assign**  
> Let another object run this script, e.g. as key script of a user, see
> **otpme-user**(1), or as mount script of a share, see
> **otpme-share**(1).
>
> **add:signature**, **delete:signature**  
> Sign the script, and delete a signature, see **Signature Management**.
>
> **verify:signature**, **view:signatures**  
> Check the signatures without reading the content.

Adding and removing ask first; the global option **-f** skips the
question.

**add_acl *script* *owner_type* *owner* *acl*\[:*value*\]\[,*acl*\[:*value*\]\]**  
Give a role or a token one or more ACLs on this script.  
*owner_type* is **role** or **token**. *owner* names it the way
**list_acls** prints it: a role as *site/name*, or by its name alone on
its own site; a token as *user/token*. An ACL can carry a value, for
example **view:script**. To give several ACLs at once, separate them
with commas: **view:script,assign**.  
Needs the ACL **add:acl**.

**del_acl *script* *acl*\[,*acl*\]**  
Take those ACLs away again.  
Here an *acl* is the whole entry, owner and all, the way **list_acls**
prints it: **role:berlin/helpdesk:view:script**.  
Needs the ACL **delete:acl**.

**list_acls *script***  
Show the ACLs that lie on this script, i.e. who may do what with it.  
Needs the ACL **view:acl**.

**enable_acl_inheritance *script***  
Let a move of the script swap its default ACLs: what the old unit handed
down is taken away, and what the new unit hands down is given. It does
not by default; a move then leaves the ACLs of the script as they are.

Only a move asks this. A new script gets the default ACLs of its unit,
and **add_acl -a** or **-r** on a unit reach it either way. A move with
**--keep-acls** leaves its ACLs alone all the same.

A move by somebody who does not hold **add:acl** and **delete:acl** on
the script leaves its ACLs alone as well, and says so. Otherwise moving
an object into a unit would be a way of handing yourself the default
ACLs of that unit.

Needs the ACL **enable:acl_inheritance**.

**disable_acl_inheritance *script***  
A move leaves the ACLs of the script as they are again.  
Needs the ACL **disable:acl_inheritance**.

## Configuration

A script has four config parameters, see **CONFIG PARAMETERS**.

**config** \[**-d**\] \[**-a**\] *script* *parameter* \[*value*\]  
Set a parameter on the script.

**-d**  
Remove the parameter from the script, or with a value only that one
value from a list. It is not set back to a default: what applies
afterwards is what the units or the site say.

**-a**  
Append the value to a parameter that holds a list, instead of replacing
what is there.

Needs the ACL **set:config:\<parameter\>**.

**show_config *script* \[*parameter*\]**  
The parameters set on the script itself, or only the one named. Nothing
is shown for a parameter that the script gets from a unit or from the
site.  
Needs the ACL **view:config:\<parameter\>**.

**get_config *script* *parameter***  
What the parameter comes to for the script, once the script, its units
and the site have been looked at. So this answers what applies, where
**show_config** answers what was set here.  
Needs the ACL **view:config:\<parameter\>**.

**description *script* \[*description*\]**  
Set the description. Without one OTPme asks and offers the current text
for editing.  
Needs the ACL **edit:description**.

**info** \[**--language** *LANG*\] *script* \[*info*\]  
Set free-form info text. If *info* is omitted, the current info text is
opened in the editor named by the **EDITOR** environment variable.  
Without **--language** the text is the administrator's own note. Nothing
shows the info of a script to a user, so a text for a language stays a
note as well.  
Needs the ACL **edit:info**.

**dump_info** \[**--language** *LANG*\] *script*  
Write one of those texts to stdout. **--language** picks which one;
without it you get the note of the administrator.  
Needs the ACL **view:info**.

## Object Changelog

Every change to the object writes an entry: who made it, when, and what
was done. A change can carry a comment of its own, through the global
option **--changelog**.

Unless the **changelog** config parameter says otherwise. It is read
along the cascade (script, unit, site), and nothing is written where it
is off. Without any value anywhere it is on.

A **copy** writes an entry on both scripts: **copy to** on the script,
and **copy from** on a script it replaces.

An *entry_id* is the number the listing shows in front of an entry,
counted from 0.

Only the comment of an entry can be changed or removed. What was done
and by whom stays as it is.

A command that changes something asks first; the global option **-f**
skips the question.

**changelog *script***  
Show the changelog of the script, one entry per line: its *entry_id*,
the time, who made the change and what was done, then a detail in round
brackets and the comment in square brackets where there are any. Needs
the ACL **view:changelog**.

**edit_changelog *script* *entry_id* *comment***  
Set the comment of that entry, or replace the one it has. That writes an
entry of its own. Needs the ACL **edit:changelog**.

**del_changelog *script* *entry_id***  
Remove the comment of that entry. The entry itself stays, and an entry
without a comment is refused. That writes an entry of its own. Needs the
ACL **edit:changelog**.

**clear_changelog *script***  
Remove every entry of the changelog. Afterwards it holds one entry: that
it was cleared.  
This needs more than the ACL **clear:changelog**: the config parameter
**allow_changelog_clearing** has to allow it (see **otpme**(7)). It is
true by default, but where no value is found at all, clearing is
refused. A value set on the token you are signed in with counts first.
Without one, the value of the script counts, read along its cascade.

## Export and Cleanup

**export** \[**--password** *password*\] *script*  
Write the whole object of the script to stdout, as JSON: its content,
signatures, ACLs, policies, config parameters and the rest. **otpme-tool
import** reads it back.  
Without **--password** it is written in clear, the content too. With
one, a key is derived from that password and the content is encrypted
with it; the salt goes into the output, so the password is all you need
to read it back.  
The content is in it, so **export** shows what **dump** shows.  
Needs the ACL **export**.

**remove_orphans *script***  
Remove references to objects that are gone: signatures of users that
were deleted, orphan ACLs and policies.  
It asks once for what it found; the global option **-f** skips the
question.  
Needs the ACL **remove:orphans**.

# OPTIONS

Every option belongs to one command and is described with that command
above.

Global options work with every command, see **otpme**(1).

# CONFIG PARAMETERS

Set them with **config**, see **Configuration**. A value is looked up on
the script, then on its unit and the units above it, then on the site;
the first one found counts. A parameter the site names in
**force_site_config_parameters** is taken from the site, whatever the
script or its units say. The full descriptions are in **otpme**(7).

**auto_sign (bool, default: false)**  
Whether **add** signs the script, as **--sign** does; so do **add -r**,
**edit** and a **copy** to a new script. A value on the token you are
signed in with counts first. **enable_autosign** of your user signs as
well, see **otpme-user**(1).

**auto_revoke (bool, default: true)**  
Whether a signature is revoked when it goes: when you sign again with
the same tags, and for all signatures when the script is deleted. A
value on the token you are signed in with counts first.

**changelog (bool, default: true)**  
Whether the commands that change the script write an entry into its
changelog, see **Object Changelog**.

**allow_changelog_clearing (bool, default: true)**  
Whether **clear_changelog** is allowed on the script. A value on the
token you are signed in with counts first, see **Object Changelog**.

Set on the site or a unit, not on the script:

**max_script_name_len (int, default: 64)**  
The longest name a script may get, checked by **add** and **rename**.

# EXAMPLES

## A login script for a user

**otpme-script add linux/login.sh ./login.sh**  
Add a login script you wrote; **./login.sh** is a file on your host, and
the script is stored as **login.sh** in the unit **linux**.

**otpme-script sign linux/login.sh**  
Sign it with your key; you are shown what is signed and asked first.

**otpme-user login_script alice linux/login.sh**  
Logins of **alice** run it, see **otpme-user**(1). This needs **assign**
on the script.

**otpme-tool add_signer --signer-type login_script 'role\|example.org/berlin/admins'**  
On a host: run a login script only with a signature of an admin, see
**otpme-tool**(1).

## Changing a script

**otpme-script dump linux/login.sh**  
Print what is in it now.

**otpme-script edit --sign linux/login.sh**  
Change it in your editor; on save it is signed again, so hosts with a
login script signer still run it.

**otpme-script verify_sign linux/login.sh**  
Check that the signatures fit the new content.

## Your own key script

**otpme-script copy scripts/key_script.sh linux/key_script.sh**  
A copy of the key script the site came with, to change; it has no
signatures yet.

**otpme-script edit --sign linux/key_script.sh**  
Change it and sign it.

**otpme-user key_script alice linux/key_script.sh**  
**alice** uses it from now on.

# AUTH ON ACTION HOOKS

An auth on action policy can ask for a login again before these actions.
See **Auth On Action Policy** in **otpme-policy**(1). A script has the
hooks every object type has, and these; a command of another name is in
brackets:

> add_sign, del_sign, dump, set_config_parameter (config), sign.

# FILES

*/etc/otpme/scripts/*  
On a node: the scripts a new site gets, one script per file, in the unit
**scripts**.

*/var/lib/otpme/tree/*  
The objects of the realm. A script is the directory *\<name\>.script* in
the directory of its unit, e.g.
*\<realm\>.realm/\<site\>.site/scripts.unit/key_script.sh.script/*, with
its content and signatures in *object.json*, the content encrypted. It
is synced to the nodes only, not to the hosts. Change it with the
commands above, not in the file.

*/var/cache/otpme/offline/\<user_uuid\>/scripts/*  
On a host: the scripts of a user as the last login brought them, with
their signatures: **login.script**, **key.script** and
**ssh-agent.script**.

*\~/.otpme/edit/*  
The file **edit** opens in your editor.

# SEE ALSO

**otpme**(1), **otpme**(7), **otpme-unit**(1), **otpme-user**(1),
**otpme-token**(1), **otpme-share**(1), **otpme-node**(1),
**otpme-host**(1), **otpme-policy**(1), **otpme-trash**(1),
**otpme-tool**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
