# NAME

otpme-share - manage OTPme file shares

# SYNOPSIS

**otpme-share** *command* \[*options*\] \[*share*\]

# DESCRIPTION

**otpme-share** manages file shares in the OTPme system. A share
provides access to a directory tree and can optionally be encrypted.

Shares support two types of scripts: An **add script** (default:
add_share.sh) is automatically executed when a share is created to set
up the share directory structure. A **mount script** (default:
mount_share.sh) can be configured to run each time a user mounts the
share. Scripts are run by scriptd as **ROOT_SCRIPT_USER** and
**ROOT_SCRIPT_GROUP** (**nobody** and **nogroup** by default, see
**otpme.conf**(5)), never as root and never as the OTPme user. A script
that has to mount something or write outside its own directories
therefore needs **sudo** for these commands. The default scripts for new
shares can be configured via the **default_share_add_script** and
**default_share_mount_script** config parameters at site or unit level.

# HOME SHARES

A normal share hands out its root directory to everybody. A **home
share** hands out *share_root***/***home_dir* instead, so every user
gets their own directory and sees nothing else. The directory is created
on the first mount, owned by the user and by default with mode 0700 (see
**home_share_permissions**).

Two naming schemes are available, chosen when the share is created:

> **--home-share**  
> The directory is named after the user UUID. Renaming a user keeps the
> directory.
>
> **--home-share-uid**  
> The directory is named after the user name (uid), which is what one
> expects below e.g. /home. Implies **--home-share**.

A **root mount token** gets no home dir and mounts *share_root* itself,
so it reaches the home dirs of all users (see **add_root_mount_token**).

Home shares can be encrypted. Every home dir is then encrypted on its
own, with a share key per user, which is why an encrypted home share has
no root mount token.

# RESTORE SHARES

A restore share shows the backups of another share. It has no directory
of its own: a mount of it reads from the backup server of the share it
was made for. What you see at the top are the snapshots, one directory
each, and below a snapshot the share as it was at that time. Nothing can
be written.

It is made with **add --restore** *share*, which names the share whose
backups it shows. That share has to be in your site. Its backups must be
made with **backup_mode** set to **tree**, and the mount takes
**backup_server**, **backup_key** and **backup_repo_password** from it,
see **otpme-backup**(1).

The restore share takes over what decides who sees what: whether it is a
home share and of which kind, the mode of the home dirs, the encryption
and the forced group. So on a restore share of a home share every user
finds the backups of their own home dir and nothing else, and a root
mount token finds all of them. With a forced group only its members can
mount. No script is run, and none of the other options of **add** is
looked at.

Who may mount it is decided on the restore share itself, like for any
share, with **add_token** and the commands next to it.
**--restore-token** *token* adds a first token right away; it has to be
a token of the share the backups are of. For an encrypted share the
mount reads the share key of the user from that share, so only a user
who has a key there can read the backups.

A change to a restore share is not put into the list a host keeps for
later logins, unless **--persist-mount** is given. A restore share
cannot be backed up itself.

# COMMANDS

## Telling the hosts

A share is mounted when a user logs in. A command that changes who may
mount a share can tell the hosts right away, so that the share comes or
goes without a new login. Such a command takes these four options:

**--share-notify, **--no-share-notify****  
Tell the hosts, or do not. Without either the config parameter
**send_share_notifications** decides, which is false by default, see
**otpme**(7).

**--persist-mount, **--no-persist-mount****  
A host keeps a list of the shares of a login, which it mounts again when
the user logs in without a connection to the site. With
**--persist-mount** the change goes into that list as well, with
**--no-persist-mount** it holds for the running login only. Without
either the change goes into the list, except for a restore share.

Only the hosts are told on which a user is logged in with a token the
change is about. The user **root** is never told.

## Share Management

**add \[**--home-share**\] \[**--home-share-uid**\] \[**--force-group** *group*\] \[**--force-directory-mode** *mode*\] \[**--force-create-mode** *mode*\] \[**--crypt**\] \[**--no-key-gen**\] \[**--block-size** *size*\] \[**--restore** *restore_share*\] \[**--restore-token** *token*\] *share***  
Create a share.  
It is created in the **shares** unit of your site; a path puts it into
another unit, and **move** takes it there afterwards. The name is turned
into lower case.  
OTPme runs the add script of the share and hands it the directory
*share_root*/*share*. The script has to create that directory: it
becomes the root directory of the share, and a share whose directory is
not there after the script is refused. **share_root** is a config
parameter, **/otpme-mounts/** by default. The script is the one
**default_share_add_script** names. The **add_share.sh** OTPme comes
with is a template in which every line is a comment: it creates nothing
until you fill it in, or until the directory is made by hand before. The
mount script that **default_share_mount_script** names is set as well,
but not enabled.  
Neither script runs as root. Both run as the user and the group that
**ROOT_SCRIPT_USER** and **ROOT_SCRIPT_GROUP** name in the config file,
**nobody** and **nogroup** by default, see **otpme.conf**(5). An add
script that has to create a directory outside of what that user may
write therefore needs **sudo** for it.  
With **--crypt** you are asked for a master password, twice. The share
key is made from it on your machine and stored in the share for your
user, and the token you are logged in with is added to the share. So
this cannot be done from a script that has no terminal. An encrypted
home share has no key of its own, and nothing is asked.  
With **--restore** none of this is done, see **RESTORE SHARES** above.
The other options are described under **Creation Options** below.  
Needs the ACL **add:share** on the unit.

**--home-share**  
Create a home share (see **HOME SHARES** above). Each user gets their
own subdirectory, named after the user UUID.

**--home-share-uid**  
Create a home share whose subdirectories are named after the user name
(uid) instead of the user UUID. Implies **--home-share**.

**del \[**--no-trash**\] \[**--share-notify**\|**--no-share-notify**\] \[**--persist-mount**\|**--no-persist-mount**\] *share***  
Delete a share. It goes to the trash, from where **otpme-trash**(1) can
bring it back; **--no-trash** deletes it right away. The directory of
the share and the data in it stay where they are.  
You have to type the name of the share to confirm; the global option
**-f** skips that. OTPme says before which tokens and roles are assigned
to the share. For an encrypted share it also says that the share keys
are deleted with it: its data can then only be read by someone who has
the master password.  
The hosts are told to unmount the share, see **Telling the hosts**
above.  
Needs the ACL **delete:object** on the share, or **delete:share** on the
unit it sits in.

**show \[**-a**\] \[**-z** *N*\] \[**--fields** *F1,F2*\] \[**--limit** *N*\] \[**--role-limit** *N*\] \[**--token-limit** *N*\] \[**--host-limit** *N*\] \[**--group-limit** *N*\] \[**--node-limit** *N*\] \[**--pool-limit** *N*\] \[**--policy-limit** *N*\] \[**--sort-by** *field*\] \[**--reverse**\] \[**--raw**\] \[**--csv**\] \[**--csv-sep** *sep*\] \[*share*\]**  
Without a share: a table of all of them, with their unit, whether they
are enabled, their root directory, whether they are encrypted, read-only
and ask for a signed SOTP, the mount timeout, the block size, the forced
group and modes, their roles and tokens, whether they are limited to
hosts, their hosts, host groups, nodes and pools, and their policies.

**-a**  
Also the shares you may only look at, not just the ones you may change.

**-z *N***  
How many shares to print.

**--fields *F1,F2***  
Print these columns and no others, in the order they are named. The
names are the ones in the header of the table. A name with a **+** in
front is added to the columns that are shown anyway, and one with a
**-** is left out of them.

**--limit *N*, **--role-limit** *N*, **--token-limit** *N*, **--host-limit** *N*, **--group-limit** *N*, **--node-limit** *N*, **--pool-limit** *N*, **--policy-limit** *N***  
How many items to print per share, and the same for one kind of them
alone. Five of each are printed by default, and 30 where the table has
one share only.

**--sort-by *field*, **--reverse****  
Which column to sort by, and the other way round.

**--raw, **--csv**, **--csv-sep** *sep***  
For reading with something other than your eyes: **--raw** leaves the
header and the borders out, **--csv** prints one row per line with **;**
between the columns, and **--csv-sep** uses another separator.

A column you may not see says **-**. Which ACL opens which column is the
**view:** ACL of that value. A token or a role that is disabled has a
**(D)** behind it.  
With a share named, this prints the object itself instead of a table
row: one value per line. That is where the home share settings, the
scripts, and the master password, root mount and no mount tokens are,
which the table does not show.

**list \[**-a**\] \[**--attribute** *attribute*\] \[*regex*\]**  
List the share names, and with a regex only those that match it. You get
the shares you may change; **-a** adds those you may only look at.  
**--attribute** matches the regex against that attribute instead of the
name: **list --attribute encrypted True** lists the encrypted shares. A
value that is not text has to be spelled out — **\*** matches none of
it.

**enable \[**--share-notify**\|**--no-share-notify**\] \[**--persist-mount**\|**--no-persist-mount**\] *share***  
Enable a disabled share.  
The hosts are told to mount it, see **Telling the hosts** above. A no
mount token is left out.  
Needs the ACL **enable:object**.

**disable \[**--share-notify**\|**--no-share-notify**\] \[**--persist-mount**\|**--no-persist-mount**\] *share***  
Switch a share off without deleting it. A disabled share cannot be
mounted.  
The hosts are told to unmount it, see **Telling the hosts** above. That
goes to the no mount tokens as well.  
Needs the ACL **disable:object**.

**rename *share* *new_name***  
Rename a share.  
Only the object gets the new name. The root directory stays the one it
was, and no host is told: a share is mounted by its name, so a host that
has it mounted, or remembers it, still asks for the old one.  
So it is best to **disable** the share first and to **enable** it again
after the rename. With **--share-notify**, or with
**send_share_notifications** set, that tells the hosts to unmount the
old name and to mount the new one.  
Needs the ACL **rename:object**.

**move \[**--keep-acls**\] *share* *unit***  
Move the share into another unit of the same site. **--keep-acls**
leaves the ACLs of the share as they are.  
A share does not inherit ACLs by default, see **enable_acl_inheritance**
below, so without that the move changes none of them anyway.  
Needs the ACL **move** on the share and **add:share** on the new unit.

**touch *share***  
Re-index the object to fix potential index problems.  
Needs the ACL **touch**.

## Share Configuration

**root_dir *share* *path***  
Set the directory the share hands out.  
It has to exist, and it has to be below **share_root**, which is
**/otpme-mounts/** by default. **share_root** is a config parameter of
the unit and the site that only an admin can set, so whoever may change
a share cannot point it at any directory of the node. A path with **..**
or a symlink in it is resolved first, and what it resolves to is what is
checked and kept.  
No data is moved. What is below the old directory stays there and is not
served any more.  
Needs the ACL **edit:root_dir**.

**force_group *share* \[*group*\]**  
Give every file and directory that is created on the share to this
group. A user can then not hand a file to another group either. Without
a *group* the forced group is taken away.  
The group has to be known on the node that serves the share. A user who
is not a member of it cannot mount the share; **root** can.  
A share that is mounted follows within a second. A user who is not in
the new group loses access to the share until they are, and mount it
again.  
Needs the ACL **edit:force_group**.

**force_create_mode *share* *mode***  
Create every file on the share with exactly this mode, whatever the
program and the umask of the user ask for. The mode of a file can then
not be changed any more.  
The mode is written the way Python writes it, e.g. **0o660**. **0o000**,
the default, forces nothing.  
A share that is mounted follows within a second.  
Needs the ACL **edit:force_create_mode**.

**force_directory_mode *share* *mode***  
The same for directories, e.g. **0o770**.  
Needs the ACL **edit:force_directory_mode**.

**home_share_permissions *share* *mode***  
The mode the home dir of a user is created with on a home share, written
like the modes above, e.g. **0o750**. The default **0o700** keeps the
users out of each others home dirs.  
A home dir is created at the first mount of its user. One that is there
keeps its mode. A share that is not a home share is refused.  
Needs the ACL **edit:home_share_permissions**.

**enable_ro *share***  
Make the share read-only: everything that would change a file, a
directory or their modes and owners is refused. A share that is mounted
follows within a second.  
Needs the ACL **enable:read_only**.

**disable_ro *share***  
Let the share be written to again.  
Needs the ACL **disable:read_only**.

**mount_timeout *share* *timeout***  
How long a mount keeps a connection to the node that it does not use.
After that time the connection is closed; the share stays mounted, and
the next access to it connects again.  
The *timeout* is in seconds, or a number with a unit: **10m**, **2h**,
**1D**. **0**, the default, keeps the connection as long as the mount.  
A host gets the timeout when it mounts the share, so a mount that is
there already keeps the old one.  
Needs the ACL **edit:mount_timeout**.

**description *share* \[*description*\]**  
Set the description. Without one OTPme asks and offers the current text
for editing.  
Needs the ACL **edit:description**.

**info \[**--language** *LANG*\] *share* \[*info*\]**  
Set free-form info text. If *info* is omitted, the current text is
opened in the editor named by the **EDITOR** environment variable.  
Without **--language** the text is the administrator's own note about
the object, which no user is ever shown. With a language it is text for
the users in that language.  
Needs the ACL **edit:info**.

**dump_info \[**--language** *LANG*\] *share***  
Print the info text, of that language or the administrator's own.  
Needs the ACL **view:info**.

## Mount Script

The mount script runs on the node every time somebody mounts the share,
before the mount is answered. It can make sure the directory is there,
e.g. mount the file system it is on. If it fails, the mount fails with
it, and the host tries the next node of the share.

The script gets the name of the share as **$share_name** and its root
directory as **$share_root**, and **$force_group**,
**$force_create_mode** and **$force_directory_mode** where the share has
them. It does not run as root, see **add** above.

A new share gets the script **default_share_mount_script** names,
switched off. The **mount_share.sh** OTPme comes with is a template in
which every line is a comment.

**mount_script *share* *mount_script* \[**--** *script_options*\]**  
Set the mount script of the share.  
The script is written as its path inside the site, e.g.
**scripts/mount_share.sh**, and it has to be a script of the site of the
share. What follows the **--** is handed to the script as its arguments,
at every mount.  
An empty name, **""**, takes the script away. That is refused while the
mount script is enabled.  
Needs the ACL **edit:mount_script** on the share and the ACL **assign**
on the script: a script that is assigned runs for this share, so the
script has to allow it.

**enable_mount_script *share***  
Run the mount script from now on. A share without a mount script is
refused, and so is one whose script is gone.  
Needs the ACL **enable:mount_script**.

**disable_mount_script *share***  
Do not run the mount script any more. The script stays set.  
Needs the ACL **disable:mount_script**.

## Encryption

An encrypted share is made with **add --crypt**; a share cannot be made
encrypted later, or plain again.

The data is encrypted on the host, before it leaves it. The node stores
what it gets: file names and file contents reach it encrypted.

There is one share key, made from the master password. The share keeps a
copy of it for every user who has a token on the share, each encrypted
for that user, so that only they can open it. A copy is made when the
first token of a user is added and removed with their last one, see
**Token and Role Management** below. A home share has a key per user
instead, see **HOME SHARES** above.

Whoever knows the master password can make the key again, which is what
a master password token is for, see **Master Password Token** below.

**get_share_key *share* *user***  
Print the copy of the share key the share keeps for this user. It is
printed the way it is stored, encrypted for the user, so nobody else can
do anything with it.  
Needs the ACL **view:share_key**. An auth on action policy can ask you
to authenticate again for it, see **otpme-policy**(1).

## SOTP Signing

A host mounts a share with an SOTP, a one-time password of the login
session of the user. With SOTP signing enabled the host also has to sign
that SOTP, with the sign private key of the user. The share keeps a copy
of the sign public key of every user that has a token on it, and the
node checks the signature against that copy.

What that buys: a user of another site cannot get at the share with an
SOTP alone. Whoever controls the nodes of that site can produce a valid
SOTP and can change the public key of the user there, but cannot touch
the copy inside the share.

On a share signing is all or nothing. Every user has to sign, so a user
whose key the share does not hold cannot mount it at all. An access
group can make an exception for users without a key, see
**otpme-accessgroup**(1); a share cannot.

A share with SOTP signing takes no roles, because a role would bring in
tokens whose users have no key here.

A user who makes a new key pair loses access until
**update_sign_public_keys** takes the new key over. That is on purpose:
updating the copy by itself would hand the site of the user the very
control the copy takes away from it.

**enable_sotp_signing *share***  
Require the hosts to sign the SOTP they mount with.  
The keys of all users that have a token on the share are copied into it,
whatever kind of token it is: a no mount, a root mount or a master
password token counts as well. If one of them has no sign public key, or
if a role is assigned to the share, nothing is changed and the users
without a key are named.  
The hosts are not told. A host that has the share mounted finds out when
it connects the next time, and signs from then on.  
Needs the ACL **enable:sotp_signing**.

**disable_sotp_signing *share***  
Do no longer require it. The copied keys are removed with it; enabling
it again reads them from the users anew.  
Needs the ACL **disable:sotp_signing**.

**update_sign_public_keys *share* \[*username*\]**  
Take over the keys the users have now, all of them or only *username*. A
key that is the same as the copy is left alone.  
Without a *username* it also removes the keys of users that have no
token on the share any more, and it names the users that have no key at
all and goes on. With one, a user without a token on the share or
without a key is refused.  
Only with signing enabled. Needs the ACL **edit:sign_public_keys**.

## Token and Role Management

Who may mount a share is said with tokens, not with users: a user mounts
the share when they are logged in with a token that is on it, or that is
in a role that is on it. The share is then mounted for them at login.

A *token_path* is written as *user***/***token*. The token can be one of
any site of the realm.

The four options that tell the hosts are described under **Telling the
hosts** above.

**add_token \[**--share-notify**\|**--no-share-notify**\] \[**--persist-mount**\|**--no-persist-mount**\] *share* *token_path***  
Let this token mount the share. The hosts are told to mount it, unless
the share is disabled.  
On an encrypted share the user of the token needs a copy of the share
key. If they have none yet, OTPme takes your own copy and asks your
machine to encrypt it anew for that user. So you need a share key of
this share yourself, and it cannot be done from a script that has no
terminal. An encrypted home share is the exception: nothing is copied,
the user makes their own key at their first mount.  
With a forced group, a token whose user is not in that group is refused,
unless you are an admin. With SOTP signing the sign public key of the
user is copied into the share, and a user without one is refused.  
Needs the ACL **add:token**. On an encrypted share that is no home share
it needs **view:share_key** as well, because it looks at the share keys.

**remove_token \[**--keep-share-key**\|**--remove-share-key**\] \[**--share-notify**\|**--no-share-notify**\] \[**--persist-mount**\|**--no-persist-mount**\] *share* *token_path***  
Take the token off the share. The hosts are told to unmount it, unless
the token still reaches the share through a role.  
On an encrypted share the share key of the user goes with their last
token, and a no mount token counts as one. **--keep-share-key** leaves
the key in the share; the user then gets the share back with their next
token, without anybody having to copy a key. On a home share the key is
kept by default, because it is the only key the home dir of that user
can be read with; **--remove-share-key** removes it nevertheless.  
With SOTP signing the sign public key of the user goes with their last
token as well.  
Needs the ACL **remove:token**.

**list_tokens \[**--return-type** *TYPE*\] \[**--token-types** *t1,t2*\] *share***  
List the tokens assigned to the share, by their path. Disabled tokens
are listed too.  
**--return-type** selects what to print instead (**name**, **read_oid**,
**full_oid**, **uuid**) and **--token-types** lists only tokens of the
given types.  
The tokens of the roles are not in this list, and neither are the master
password, root mount and no mount tokens; **show** *share* prints
those.  
Needs the ACL **view:tokens**.

**add_role \[**--share-notify**\|**--no-share-notify**\] \[**--persist-mount**\|**--no-persist-mount**\] *share* *role***  
Add a role to the share. Every token of the role, and of the roles
inside it, may then mount it, and the hosts are told so.  
The role is looked for in the site of the share, or written as
*site***/***role* to take one from another site of the realm.  
An encrypted share takes no role, because a role would bring in users
who have no share key. A share with SOTP signing takes none either, see
**SOTP Signing** above.  
Needs the ACL **add:role**.

**remove_role \[**--share-notify**\|**--no-share-notify**\] \[**--persist-mount**\|**--no-persist-mount**\] *share* *role***  
Remove a role from the share. The hosts are told to unmount it for the
tokens of the role that do not reach the share another way.  
A UUID is taken as well, which is how a reference to a role that is gone
is cleared out.  
Needs the ACL **remove:role**.

**list_roles *share***  
List the names of the roles assigned to the share. Disabled roles are
listed too. A role of another site is written as *site***/***role*.  
Needs the ACL **view:roles**.

**list_users \[**--return-type** *TYPE*\] *share***  
The users the tokens of the share belong to. One user with three tokens
on the share is named once.  
Needs the ACL **view:tokens**.

## Host Management

The tokens say who may mount a share. The hosts say where: a share can
be limited to a list of hosts.

Without a limit the share is mounted on every host its users log in at,
and the lists below are kept but not looked at. With **limit_hosts**
only these hosts may mount it:

-   the hosts that are on the share,

-   the hosts of the host groups that are on the share, as long as the
    group is enabled,

-   the hosts of the roles that are on the share, as long as the role is
    enabled.

So a role on a share counts twice: its tokens may mount, and its hosts
are places to mount at.

The node checks the host when the share is mounted and goes on checking
while it is mounted. A host that is taken off the list loses its access
within a second, whether it was told or not.

A *host* is looked for in the site of the share, or written as
*site***/***host* to take one from another site of the realm. The same
goes for a *group*, written as *site***/***group*. A host name is unique
within its site only, so two sites can each have a host of the same
name.

The four options that tell the hosts are described under **Telling the
hosts** above. As long as the share is not limited these commands tell
no host: nothing changes for any of them. A host of another site is told
as well, but only while it has a share of this site mounted, because
only then it listens to this site. Otherwise the change reaches it with
the next login.

**limit_hosts \[**--share-notify**\|**--no-share-notify**\] \[**--persist-mount**\|**--no-persist-mount**\] *share***  
Limit the share to its hosts. The hosts that are not on the list are
told to unmount it.  
Fill the list first. A limited share with no host, no host group and no
role with hosts can be mounted nowhere.  
Needs the ACL **limit_hosts**.

**unlimit_hosts \[**--share-notify**\|**--no-share-notify**\] \[**--persist-mount**\|**--no-persist-mount**\] *share***  
Take the limit away again. The lists stay as they are. The hosts are
told to mount the share, unless it is disabled.  
Needs the ACL **unlimit_hosts**.

**add_host \[**--share-notify**\|**--no-share-notify**\] \[**--persist-mount**\|**--no-persist-mount**\] *share* *host***  
Put a host on the share. On a limited share the host is told to mount
it, unless the share is disabled.  
Needs the ACL **add:host**.

**remove_host \[**--share-notify**\|**--no-share-notify**\] \[**--persist-mount**\|**--no-persist-mount**\] *share* *host***  
Take a host off the share. On a limited share the host is told to
unmount it, unless it still is on the list through a host group or a
role.  
Needs the ACL **remove:host**.

**list_hosts \[**--return-type** *TYPE*\] *share***  
List the hosts that are on the share itself, by name. The hosts of its
host groups and roles are not in this list. **--return-type** selects
what to print instead (**name**, **read_oid**, **full_oid**,
**uuid**).  
Needs the ACL **view:hosts**.

**add_group \[**--share-notify**\|**--no-share-notify**\] \[**--persist-mount**\|**--no-persist-mount**\] *share* *group***  
Put a host group on the share. A group is a host group by the hosts it
holds, see **otpme-group**(1); its tokens and users play no part here.
On a limited share the hosts of the group are told to mount it, unless
the share is disabled.  
Needs the ACL **add:group**.

**remove_group \[**--share-notify**\|**--no-share-notify**\] \[**--persist-mount**\|**--no-persist-mount**\] *share* *group***  
Take a host group off the share. On a limited share the hosts that are
on the list no more are told to unmount it.  
Needs the ACL **remove:group**.

**list_groups \[**--return-type** *TYPE*\] *share***  
List the names of the host groups that are on the share. A group of
another site is written as *site***/***group*. **--return-type** selects
what to print instead (**name**, **read_oid**, **full_oid**, **uuid**).
Disabled groups are listed too, though their hosts do not count.  
Needs the ACL **view:groups**.

## Master Password Token

A master password token may mount an encrypted share with the master
password instead of a share key, with **otpme-mount
--master-password-mount, see** **otpme-mount**(1). That is the way back
in when no share key is left, and the way a share key gets into a share
that was taken over with **--no-key-gen**.

The token needs no other assignment to the share, and its user gets no
share key from this. Only an encrypted share takes one.

**add_master_password_token *share* *token_path***  
Let the token mount the share with the master password.  
With SOTP signing the sign public key of the user is copied into the
share, and a user without one is refused.  
Needs the ACL **add:master_password_token**.

**remove_master_password_token *share* *token_path***  
Take that away again. OTPme asks before it does so, and the question
says when this is the last master password token of the share: without
one nobody can mount the share with the master password any more. The
question is all there is. With the global option **-f**, or with a
**confirmation_policy** other than **paranoid**, nothing is asked and
the last token is removed without a word.  
Needs the ACL **remove:master_password_token**.

## Root Mount Token

A root mount token gets no home dir. It mounts the root directory of a
home share itself and so reaches the home dirs of all users, see **HOME
SHARES** above. It is made for places like a university: the students
each see only their own home dir and hand in their exams there, and a
lecturer with a root mount token reaches the home dirs of all of them.

Only a home share that is not encrypted takes one: on an encrypted home
share every home dir has a key of its own, so a mount of the root could
read none of them. The token needs no other assignment to the share.

**add_root_mount_token \[**--share-notify**\|**--no-share-notify**\] \[**--persist-mount**\|**--no-persist-mount**\] *share* *token_path***  
Let the token mount the root directory of the home share. What the token
gets from the share changes, so the hosts are told to mount it, like
with **add_token**.  
With SOTP signing the sign public key of the user is copied into the
share, and a user without one is refused.  
Needs the ACL **add:root_mount_token**.

**remove_root_mount_token \[**--share-notify**\|**--no-share-notify**\] \[**--persist-mount**\|**--no-persist-mount**\] *share* *token_path***  
Take that away again. The hosts are told to unmount the share for the
token, like with **remove_token**.  
Needs the ACL **remove:root_mount_token**.

## No Mount Token

A no mount token is on the share like a normal token — its user gets a
share key, and it may mount the share — but the share is not mounted for
it by itself. It is left out when the shares are mounted at login, and
the hosts are not told to mount for it. Mounting by hand with
**otpme-mount** *share_site***/***share_name* works.

When a share is disabled or deleted the hosts are told to unmount for
these tokens too: they may have mounted it by hand.

**add_no_mount_token *share* *token_path***  
Add a token that does not get the share mounted by itself.  
The share key, the forced group and the sign public key are handled as
with **add_token**. No host is told, there is nothing to mount.  
Needs the ACL **add:no_mount_token**, and **view:share_key** where
**add_token** needs it.

**remove_no_mount_token \[**--keep-share-key**\|**--remove-share-key**\] \[**--share-notify**\|**--no-share-notify**\] \[**--persist-mount**\|**--no-persist-mount**\] *share* *token_path***  
Take the token off the share. The share key and the sign public key of
the user go with their last token, as with **remove_token**, and the two
key options do the same.  
The hosts are told to unmount the share for the token, because it may
have mounted it by hand. They are not told when the token still reaches
the share as a normal token or through a role.  
Needs the ACL **remove:no_mount_token**.

## Pool and Node Management

The nodes of a share are the nodes that serve it. A host connects to one
of them when it mounts the share. A share with no node and no pool is
served by all nodes of its site.

With nodes or pools on it, a share is served by those nodes and by the
nodes of those pools; a pool is a named list of nodes, see
**otpme-pool**(1). A disabled node and a disabled pool are left out.

A node that is not one of them refuses to mount the share. A share whose
nodes are all disabled cannot be mounted, and a login does not get it.

A host picks one of the nodes at random. It tries another one when a
node cannot be reached, when the node refuses the share, or when the
root directory of the share is not there. So every node of a share has
to hold the same files under the root directory. OTPme does not copy
them from node to node. Use storage that all the nodes share, CephFS or
NFS for example.

A host gets the list of nodes when the user logs in, and again with
every mount. No host is told about a change here. A mount on a node that
was taken off the share ends there, and the host connects to another
node of the list it has. So keep at least one node of the old list on
the share when you change its nodes. If none is left, the users have to
log in again to reach the share.

A *node* and a *pool* are of the site of the share.

**add_node *share* *node***  
Put a node on the share. The first node that is added ends the "all
nodes of the site" rule: from then on only the listed nodes serve the
share.  
Needs the ACL **add:node**.

**remove_node *share* *node***  
Take a node off the share.  
Needs the ACL **remove:node**.

**list_nodes \[**--return-type** *TYPE*\] *share***  
List the nodes that are on the share itself, by name. The nodes of its
pools are not in this list. On a share with no node and no pool it lists
all nodes of the site, which is what serves it. Disabled nodes are not
listed.  
**--return-type** selects what to print instead (**name**, **read_oid**,
**full_oid**, **uuid**).  
Needs the ACL **view:nodes**.

**add_pool *share* *pool***  
Put a pool on the share. Its nodes serve the share, and a node that is
put into the pool later does so too.  
Needs the ACL **add:pool**.

**remove_pool *share* *pool***  
Take a pool off the share.  
Needs the ACL **remove:pool**.

**list_pools \[**--return-type** *TYPE*\] *share***  
List the names of the pools that are on the share. Disabled pools are
listed too.  
**--return-type** selects what to print instead (**name**, **read_oid**,
**full_oid**, **uuid**).  
Needs the ACL **view:pools**.

## Policy Management

A *policy* is the name of a policy, not a path. It is looked for in the
site of the share. Which policies there are, and what each of them does,
is in **otpme-policy**(1).

Attaching and detaching ask before they change anything; the global
option **-f** skips the question.

**add_policy *share* *policy***  
Attach a policy to the share.  
A policy has a list of object types it is for; one that does not name
**share** is refused. So is a second policy of a type that allows only
one per object.  
Needs the ACL **assign:policy**.

**remove_policy *share* *policy***  
Remove a policy from the share.  
Needs the ACL **remove:policy**, and that one verbatim: a plain
**remove** does not cover it. Detaching a policy takes away what it
enforces, so it must not be cheaper than attaching one.

**list_policies \[**--return-type** *TYPE*\] \[**--policy-types** *t1,t2*\] *share***  
List the policies attached to the share. Use **--return-type** to select
the attribute returned (**name**, **read_oid**, **full_oid**, **uuid**).
Use **--policy-types** to list only policies of the given types; these
are policy types, not policy names.  
Needs the ACL **view:policies**.

## ACL Management

**add_acl *share* *owner_type* *owner* *acl***  
Add an access control entry.

**del_acl *share* *acl***  
Remove an access control entry.

**list_acls *share***  
Display all ACLs for the share.

**enable_acl_inheritance *share***  
Enable ACL inheritance from parent objects.

**disable_acl_inheritance *share***  
Disable ACL inheritance.

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

**changelog *share***  
Show the changelog of the share. Needs the ACL **view:changelog**.

**edit_changelog *share* *entry_id* *comment***  
Set the comment of that entry, or replace the one it has. Needs the ACL
**edit:changelog**.

**del_changelog *share* *entry_id***  
Remove the comment of that entry. The entry itself stays, and an entry
without a comment is refused. Needs the ACL **edit:changelog**.

**clear_changelog *share***  
Remove every entry of the changelog.  
This needs more than the ACL **clear:changelog**: the config parameter
**allow_changelog_clearing** has to allow it (see **otpme**(7)). It is
true by default, but where no value is found at all, clearing is
refused. OTPme asks the token you are signed in with first, then the
object.

## Import/Export

**export \[**--password** *PASS*\] *share***  
Export share configuration.

**remove_orphans *share***  
Remove orphaned object references.

# OPTIONS

## Creation Options

**--force-group *GROUP***  
Force group for the share.

**--force-directory-mode *MODE***  
Force directory creation mode.

**--force-create-mode *MODE***  
Force file creation mode.

**--crypt**  
Enable encryption for the share.

**--no-key-gen**  
Do not generate an AES key.  
This is for a directory that is already an encrypted OTPme share, and it
belongs together with **--add-share-key** of **otpme-mount**. Use it
after a move to another site, or when the share object is gone and the
data is still there. The data of such a directory can only be read with
the key it was written with, so a new key must not be made.  
OTPme keeps the settings file that is already in the directory. The key
is therefore still made the same way from the same master password. Get
it back in from the login session of root, with a token that may use the
master password of the share:  
**otpme-mount --master-password-mount --add-share-key** *share
mountpoint*  
This asks for the master password of the old share, makes the key from
it and stores it for your own token. After that the share mounts the
normal way, and you can add more tokens to it with **add_token**.  
Do not use it for a new, empty share. Such a share has no master
password settings of its own, and then every master password mount makes
a different key. Data written under such a mount cannot be read again.

**--block-size *SIZE***  
Encrypted share block size (default 4096).

**--restore *RESTORE_SHARE***  
Make a restore share that shows the backups of this share, see **RESTORE
SHARES** above.

**--restore-token *TOKEN***  
With **--restore**: add this token to the new share right away. It has
to be assigned to the share the backups are of.

## Display Options

**-a**  
Show all shares.

**-z *SIZE***  
Limit output size.

**--fields *FIELD1,FIELD2***  
Display only specified fields.

**--node-limit *N***  
Limit number of nodes shown.

**--pool-limit *N***  
Limit number of pools shown.

**--token-limit *N***  
Limit number of tokens shown.

**--role-limit *N***  
Limit number of roles shown.

**--group-limit *N***  
Limit number of groups shown.

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
Of **list**: match the regex against this attribute instead of the name.

## General Options

**--keep-acls**  
Preserve ACLs when moving share.

**--password *PASS***  
Password for encrypting exports.

**-r**  
List roles recursively.

Global options are available for all commands. See **otpme**(1) for
details.

# CONFIG PARAMETERS

Configuration parameters can be set with the **config** command and
displayed with **show_config**. For a complete description of all
available parameters and their applicable object types, see
**otpme**(7).

# EXAMPLES

**otpme-share add myshare**  
Create a share

**otpme-share add --crypt secureshare**  
Create an encrypted share

**otpme-share add --crypt --no-key-gen oldshare**  
Take over a directory that is already an encrypted share. Get the key
back in with **otpme-mount --master-password-mount --add-share-key
oldshare /mnt** (see **otpme-mount**(1)).

**otpme-share add_token myshare alice/totp**  
Add a token to the share

**otpme-share add_pool myshare europe**  
Add a pool to the share

**otpme-share add --home-share-uid homes**  
Create a home share, each user gets *\<share_root\>/\<username\>*

**otpme-share home_share_permissions homes 0o750**  
Let the home dirs group be readable

**otpme-share add_root_mount_token homes backup/login**  
Let the token "backup/login" mount the share root and reach all home
dirs

# SEE ALSO

**otpme**(1), **otpme**(7), **otpme-acls**(7), **otpme-mount**(1),
**otpme-pool**(1), **otpme-token**(1), **otpme-role**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
