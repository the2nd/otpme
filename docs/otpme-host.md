# NAME

otpme-host - manage OTPme hosts

# SYNOPSIS

**otpme-host** *command* \[*options*\] \[*host*\]

# DESCRIPTION

**otpme-host** manages the hosts of a realm: the machines people log in
to, such as notebooks, workstations and servers.

A host is not a node. A node runs the realm; a host runs **hostd** and
**confd**, and **httpd** or **backupd** only where it serves the SSO
portal or takes backups. It syncs the users, groups and tokens it needs,
so it can resolve a user and check an SSH key on its own. A password or
an OTP is checked by a node of its site, or by the host itself where the
token allows offline logins.

The host object is what the realm knows about the machine: its
certificate and its public key, the tokens and roles that may log in
there, the users and groups it syncs, its MAC address and its VLAN, and
whether it takes configuration jobs and reports an inventory.

A host object is made with **add** before the machine joins, or by the
join itself, which adds the host when it is not there yet (see
**otpme-tool**(1)).

# COMMANDS

## Host Management

**add *host***  
Create a host. The machine itself need not exist yet: this is the object
a join with a JOTP looks for. The name has to be unique in the realm: no
host and no node of any site may have it already. Where an
**objecttemplates** policy names a host template, the new host is built
from it (see **otpme-policy**(1)).  
There is no **rename**. A host is found by the name it joined with,
which is also the name in its certificate, so a machine that is renamed
leaves the realm and joins again.

**del \[**--no-trash**\] *host***  
Delete a host. It goes to the trash, from where **otpme-trash**(1) can
bring it back; **--no-trash** deletes it right away.  
The certificate of the host is revoked, and the roles and access groups
that name the host let it go first, so nothing is left pointing at it.

**show \[**-a**\] \[**-t**\] \[**-z** *N*\] \[**--fields** *F1,F2*\] \[**--limit** *N*\] \[**--token-limit** *N*\] \[**--role-limit** *N*\] \[**--policy-limit** *N*\] \[**--sort-by** *field*\] \[**--reverse**\] \[**--raw**\] \[**--csv**\] \[**--csv-sep** *sep*\] \[*host*\]**  
Show the hosts, with their tokens, roles and policies. Without a host
you get all of them.

**-a**  
Also the hosts you may only look at, not just the ones you may change.

**-t**  
Show the host templates instead of the hosts. A template is a host
object a new host is built from; a site gets one called
**host_template** when it is created.

**-z *N***  
How many hosts to print.

**--fields *F1,F2***  
Print these columns and no others. The names are the ones in the header
of the table.

**--limit *N***  
How many of each kind to print per host: tokens, roles, policies.

**--token-limit *N*, **--role-limit** *N*, **--policy-limit** *N***  
The same for one of them, where the others should stay as they are.

**--sort-by *field*, **--reverse****  
Which column to sort by, and the other way round.

**--raw, **--csv**, **--csv-sep** *sep***  
For reading with something other than your eyes: **--raw** leaves the
header and the borders out, **--csv** prints one row per line with **;**
between the columns, and **--csv-sep** uses another separator.

**list \[**-a**\] \[**--attribute** *attribute*\] \[*regex*\]**  
List the host names, and with a regex only those that match it. You get
the hosts you may change; **-a** adds those you may only look at.  
**--attribute** matches the regex against that attribute instead of the
name: **list --attribute enabled True** lists the hosts that are
enabled. A value that is not text has to be spelled out — **\*** matches
none of it.

**enable *host***  
Enable a disabled host.

**disable *host***  
Disable a host without deleting it. A disabled host is turned away by
the daemons it talks to, so it neither syncs nor logs anybody in.

**move \[**--keep-acls**\] *host* *unit***  
Move the host into another unit. Its ACLs move with it: the default ACLs
of the old unit are taken away and those of the new one are applied.
**--keep-acls** leaves the ACLs of the host as they are.

**touch *host***  
Re-index the object to fix potential index problems.

**auto_disable \[**-u**\] *host* *time***  
Set auto-disable time. It is either a relative time with a leading
**+**, e.g. **+30D**, or an absolute one, e.g. **"09:53 13.06.2023"**.
The units are **s**, **m**, **h**, **D**, **W**, **M** and **Y**, see
**otpme**(7). Use **-u** to disable the object if it was unused for the
given time.

**mac *host* *mac_address***  
Set the host's MAC address. It is what the realm recognises the machine
by when a switch port is opened without anybody logging in, see **Port
Authentication** below.

## Token and Role Assignment

A token is named by its path, *user***/***token*. A role is named by its
name, which is looked for in the site of the host, or as
*site***/***role* to take one from another site of the realm.

**add_token \[**-i** *interfaces*\] \[**--no-auto-sign**\] \[**--sign** **--tags** *tag1,tag2*\] *host* *token_path* \[*token_options*\]**  
Let this token log in to the host.

**-i *interfaces***  
Only these login interfaces, comma separated: **gui**, **tty**, **ssh**.
With a leading **-** the interface is the one that is not allowed, as in
**-gui**, and the two forms cannot be mixed.

*token_options*  
SSH options for the key of this token, written as they stand in an
**authorized_keys** line: comma separated, and a value may be quoted, as
in **command="/usr/bin/x --a,--b",no-pty**.  
They are for an SSH token, and only the options that token allows:
**cert-authority**, **command**, **restrict**, **environment**,
**from**, **no-agent-forwarding**, **no-port-forwarding**, **no-pty**,
**no-user-rc**, **no-X11-forwarding**, **permitopen**, **principals**
and **tunnel**. Anything else is dropped when the **authorized_keys**
file is written, with a warning in the log.

**--sign, **--tags** *tag1,tag2***  
Sign the token for this assignment. The signature carries the user and
this host, and the interfaces and options where they were given, so it
says what the token was allowed to do here. How signing works, and what
a signer makes of the tags, is in **otpme-role**(1). A token that cannot
be signed with **--sign** is an error.

**--no-auto-sign**  
Do not sign, whatever the **auto_sign** of the host or the **autosign**
setting of your own user says.

A token that is already assigned, with other interfaces or options, is
not added twice: OTPme asks whether to change what it has.

**remove_token \[**--keep-sign**\] *host* *token_path***  
Take the token away from the host. The signature for this assignment is
removed with it; **--keep-sign** leaves it in place.

**list_tokens \[**--return-type** *TYPE*\] \[**--token-types** *t1,t2*\] *host***  
List the tokens assigned to the host. Use **--return-type** to select
the attribute returned (**name**, **read_oid**, **full_oid**, **uuid**)
and **--token-types** to limit the listing to the given token types.

**add_role *host* *role***  
Add a role to the host. Its tokens may then log in here, with the
interfaces and options they were given in the role, and the users the
role syncs are synced to this host. The dynamic groups of the role, and
of the roles in it, are added to everybody who logs in here.  
Putting the host into a role is the other way round and another thing:
that decides which VLAN the host gets and which shares it may reach, see
**otpme-role**(1) **add_host**.

**remove_role *host* *role***  
Remove a role from the host. A UUID is taken as well, which is how a
reference to a role that is gone is cleared out.

**list_roles *host***  
List the names of the roles assigned to the host.

## Login Control

Who may log in to a host is decided by the tokens and roles it holds,
see **Token and Role Assignment** above. A host limits logins from the
moment it is made: only what is assigned to it gets in. Opened up, every
token of the REALM access group may log in, and the assignments then
only say what else a token gets there.

**limit_logins *host***  
Only let the tokens and roles assigned to this host log in. This is how
a host starts.  
It also narrows what is synced to the host, see
**enable_sync_by_login_token** below.

**unlimit_logins *host***  
Let every token of the REALM access group log in. The assignments stay
as they are, with their login interfaces and options.

On top of that the host itself can refuse a user, in its config file and
not in the realm. **VALID_LOGIN_USERS** is a list, and a user not in it
may not log in. **DENY_LOGIN_USERS** is a list of users that may not log
in whatever else says so, and it is asked first. An entry is a user
name, or *name*:*uuid* to name the user you mean and no other. Both are
checked for an interactive login and for an SSH key, see
**otpme.conf**(5).

## Signers

A signature is checked on the host, so which signatures count is
configured there and not in the realm:

> **otpme-tool add_signer --signer-type token *user\|role***

The signer is named by its OID, **user\|***realm***/***name* or
**role\|***realm***/***site***/***name*, and stored by UUID, so a rename
keeps the signer. It is added for one type of thing. With a signer of
type **token** the host only lets an SSH key log in that carries a
signature of that signer; a key without one is ignored. Who signs a
token, and with which tags, is in **otpme-role**(1). Without a token
signer every synced SSH key may log in.

The other types are for what the host runs or takes: **key_script**,
**agent_script**, **login_script**, **auth_script**, **push_script**,
**backup_script** and **share_script** for the scripts, and
**repo_mgmt**, **sw_mgmt**, **signer_mgmt**, **service_mgmt**,
**file_mgmt** and **host_mgmt** for the configuration jobs, plus
**remote_access** for a shell on the host. One type per kind of job on
purpose: whoever may install a package is not thereby allowed to change
the signers of the host, or to log in.

Root adds a signer for the whole host. A user may add one of their own
with **--private**, for the types **token**, **key_script** and
**agent_script**. The config file options **FORCE_TOKEN_SIGNERS**,
**FORCE_KEY_SCRIPT_SIGNERS** and **FORCE_AGENT_SCRIPT_SIGNERS** make the
host ignore the private ones, for everybody or only for the users they
name. See **otpme-tool**(1) and **otpme.conf**(5).

## VLAN Assignment

A host is not assigned a VLAN from here. Either the VLAN names the host,
so that the assignment belongs to the site that runs the network (see
**otpme-vlan**(1)):

> **otpme-vlan add_host *vlan* *host***

or the host names the VLAN through its **vlans** config parameter (see
**otpme**(7)):

> **otpme-host config *host* vlans *vlan***

The VLAN is returned during MAB port authentication, where the host
authenticates with its MAC address. Membership wins: the **vlans**
parameter is only looked at when no VLAN of the site answering the
RADIUS request names the host. A host that is in the VLAN only through a
role is overridden by one that names the host itself. A disabled VLAN is
skipped and said so in the log.

## Port Authentication

A switch port is opened in one of two ways, and they are not the same
thing.

With MAB the switch sends the MAC address of the machine and nobody has
logged in yet. The realm looks the address up, finds the host and
answers with its VLAN, see **VLAN Assignment** above. Set the address
with **mac**.

With 802.1X the user authenticates the port, so it happens at login. The
PAM module hands NetworkManager the name of the user and a password: the
one the user types, or, where the token type is a smartcard, an OTP made
on the card.

> **auth required pam_otpme.so do_dot1x=auto
> dot1x_token_types=yubikey_piv**

**do_dot1x** is **auto** to do it only while the network is down,
**force** to take the connection down and up again at every login, or
**false**. **dot1x_connection** names the NetworkManager connection,
**dot1x-lan** by default, and **dot1x_timeout** is how many seconds
OTPme waits for it, 10 by default. **dot1x_token_types** says which
token types to use; without it nothing is done. Nothing is done either
while the link is down, which is what keeps this out of the way of a
WLAN or an offline login. See **pam_otpme**(8).

## User and Group Listing

**--return-type** picks what these print: **name** (the default),
**read_oid**, **full_oid** or **uuid**.

**list_users \[**--return-type** *TYPE*\] *host***  
The users who own a token assigned to the host. Only the tokens the host
holds itself count here, not the ones it gets through a role.

**list_sync_users \[**--return-type** *TYPE*\] *host***  
The sync users of the host, as **add_sync_user** set them. The ones that
come with a role are not in it, see **Sync Configuration** below.  
Needs the ACL **view:sync_users**.

**list_sync_groups \[**--return-type** *TYPE*\] *host***  
The sync groups of the host.

**list_dynamic_groups *host***  
The dynamic groups of the host, with those of the roles it is in.

## Where this host is used

A command that starts with **list\_** answers what the host holds. One
that starts with **find\_** answers the other question: where the host
itself is named.

**--return-type** works as above, and a name from another site is
printed as *site***/***name*. Disabled objects are listed as well, so a
permission that is only switched off is not mistaken for one that is
gone. Each of these needs its own ACL, **find:roles** for **find_roles**
and so on.

**find_roles \[**--return-type** *TYPE*\] *host***  
The roles the host is in. They decide which VLAN it gets and which
shares it may reach, see **otpme-role**(1) **add_host**.

**find_accessgroups \[**--return-type** *TYPE*\] *host***  
The access groups the host is in. This is what carries it through MAB:
the host authenticates with its MAC address as the password, and the
access group the request is answered for has to hold the host, see
**Port Authentication** above.

**find_groups \[**--return-type** *TYPE*\] *host***  
The groups the host is in. A group matters for the shares of that group
that are limited to hosts.

**find_shares \[**--return-type** *TYPE*\] *host***  
The shares the host is named in, so the ones it may mount without a role
bringing it.

## Dynamic Groups

A dynamic group is a local group of the machine, such as **plugdev** or
**audio**. Whoever logs in through the PAM module is put into it for
that session, without being a member of anything in the realm. Two sides
are added together: the groups of the host and of the roles the host is
in, and the groups of the login token and of the roles it is in. The
roles in those roles count too, however deep they go. A group that does
not exist on the machine is skipped, with a warning in the log.

**add_dynamic_group *host* *group***  
Add a dynamic group to the host. Everybody who logs in here gets it.

**remove_dynamic_group *host* *group***  
Remove a dynamic group from the host.

The machine has the last word, in its config file.
**ALLOW_DYNAMIC_GROUPS** set to **False** switches dynamic groups off
altogether; as a list it allows only the groups it names.
**DENY_DYNAMIC_GROUPS** names the groups never to add. Deny is asked
first. See **otpme.conf**(5).

## Sync Configuration

A host does not hold the whole realm. Which users and tokens it gets is
decided by two switches, and what each of them picks is added to the
other:

**sync_by_login_token** is on from the start and picks the ones that can
log in here. While logins are limited those are the tokens assigned to
the host and to its roles, and their users; after **unlimit_logins**
they are the tokens of the REALM access group and their users.

**sync_groups** is off from the start. It picks the members of the
groups named with **add_sync_group**: the sync users of each group, the
owners of its tokens, those tokens, and the users whose default group it
is.

Each of the two takes users and tokens out of the sync of whole object
types, so a host gets every user and token of its site only while both
are off.

The sync users of the host and of its roles always come along, and so do
the default tokens of the users and the destinations of link tokens.

**add_sync_user *host* *user***  
Sync this user to the host whether or not they ever log in there, so the
machine can resolve them — where it holds their home directory, for
one.  
Needs the ACL **add:sync_user**.

**remove_sync_user *host* *user***  
Remove a sync user from the host.  
Needs the ACL **remove:sync_user**.

**add_sync_group *host* *group***  
Name a group whose members are synced to the host. It is only read while
sync groups are enabled.

**remove_sync_group *host* *group***  
Remove a sync group from the host.

**enable_sync_groups *host***  
Start reading the sync groups.

**disable_sync_groups *host***  
Stop reading them. The list stays as it is.

**enable_sync_by_login_token *host***  
Sync the users and tokens that can log in here, which is how a host
starts.

**disable_sync_by_login_token *host***  
Sync every user and token of the site instead, for a host that has to
resolve users who do not log in on it at all — the owners of files, for
one. Switched off together with **sync_groups** this is the whole site;
with sync groups on, those groups decide.

## Realm Join and Leave

A machine joins the realm with **otpme-tool join** and leaves it with
**otpme-tool leave** (see **otpme-tool**(1)). Either an admin logs in
for it, or the machine uses a one-time password.

The JOTP is the one for joining. **add** makes one, and **enable_jotp**
prints it. It is gone once the host has joined, and a LOTP for leaving
is made in its place. Leaving the realm revokes the certificate of the
host, drops its public key and makes a new JOTP, so the machine can come
back.

**enable_jotp *host***  
Allow joining with the JOTP, and print it. It is allowed by default.

**disable_jotp *host***  
Refuse the JOTP. A join then needs an admin login.

**enable_lotp *host***  
Allow leaving with the LOTP, and print it. It is allowed by default.

**disable_lotp *host***  
Refuse the LOTP. Leaving then needs an admin login.

**enable_jotp_rejoin *host***  
Print the new JOTP to the machine that is leaving. Whoever leaves the
realm can then join again without an admin login. It is off by default.

**disable_jotp_rejoin *host***  
Keep the new JOTP to yourself.

The JOTP and the LOTP are shown by **show** and by **export** to whoever
holds the ACL **view:jotp** or **view:lotp**.

## Certificates and Keys

A host gets a certificate and a key pair of its own when it joins. The
certificate is for TLS, and it is how a daemon knows which host is at
the other end of a connection.

The key pair is how a host proves that it is that host. **syncd** and
**backupd** ask for it before they answer anything: both ends sign a
challenge of the other, and each checks the answer against the public
key on the host object in the tree. A challenge older than five seconds
is refused. The private half never leaves the machine, it stays in
**hostkey.pem**; the public half is what the commands below show and
set.

The same key is the SSH host key of a remote shell — the host vouches
for it, and the other end holds that against the public key here (see
**otpme-shell**(1)).

The certificate is renewed on the machine itself, with **otpme-tool
renew_cert**. The certificate request is made there, with the key of the
host; this side only signs it.

**dump_cert *host***  
Print the certificate of the host.

**dump_ca_chain *host***  
Print the CA certificates above it, up to the CA of the site.

**get_public_key *host***  
Print the public key of the host.

**public_key *host* \[*public_key*\]**  
Replace the public key of the host. Without the key as an argument you
are asked to paste it; an empty answer takes the key away.  
The join sets this, so there is normally no reason to touch it.

## SSH

**get_ssh_authorized_keys *host* \[*user*\]**  
Ask the realm which SSH keys this host lets in. With a user the lines
come as sshd reads them; without one the keys of every user come, each
line with the user name in front. A key that needs a signature and does
not have one is left out, see **Signers** above.

On the machine itself sshd does not read this. It calls
**otpme-get-authorized-keys *username*,** which answers from the file
**hostd** keeps:

> **AuthorizedKeysCommand /usr/local/bin/otpme-get-authorized-keys**  
> **AuthorizedKeysCommandUser root**

The keys are synced before the answer, or the first login of a token
that was just added would be refused. Not more often than every 30
seconds, though: sshd runs the command on every login attempt, and
anybody who reaches port 22 can make one. A sync per attempt would let
whoever knocks at the door decide how often this host syncs.

## Configuration Jobs and Inventory

A host can be told to install a package, write a file or restart a
service. The jobs are made with **otpme-deploy**(1), and every job
carries a signature of a signer of its own type, see **Signers** above.

**config *host* allow_confd_jobs *token\|role***  
The tokens and roles that may send a job to this host. Unset means
nobody.  
Both are named by their OID, **token\|***realm***/***user***/***name*
and **role\|***realm***/***site***/***name*, and stored by UUID: a
rename keeps the permission, and a new object of the same name does not
inherit it. A token counts as named when it is in a named role, however
deep the nesting goes.

A host also reports what it runs: its system, its installed packages and
its hardware. It does that by itself; what is configured is who reads it
and where it is kept. Read it with **otpme-inventory**(1).

**config *host* allow_inventory *token\|role***  
The tokens and roles that may read the inventory of this host, named the
same way as above. Unset means nobody. A plain **view** ACL on the host
does not carry it.

**config *host* inventory_site *site***  
The site that keeps the inventory of this host. Unset means the site the
host belongs to. The site named here has to accept it, see
**inventory_trusts** in **otpme**(7).

## Object Changelog

Every change to the object writes an entry: who made it, when, and what
was done. A change can carry a comment of its own, through the global
option **--changelog**.

Unless the **changelog** config parameter says otherwise. It is read
along the cascade of the host, and nothing is written where it is off —
not for that host, and not for the ones below a unit that switched it
off. Without any value anywhere it is on.

An *entry_id* is the number the listing shows in front of an entry,
counted from 0.

Only the comment of an entry can be changed or removed. What was done
and by whom stays as it is.

A command that changes something asks first; the global option **-f**
skips the question.

**changelog *host***  
Show the changelog of the host. Needs the ACL **view:changelog**.

**edit_changelog *host* *entry_id* *comment***  
Set the comment of that entry, or replace the one it has. Needs the ACL
**edit:changelog**.

**del_changelog *host* *entry_id***  
Remove the comment of that entry. The entry itself stays, and an entry
without a comment is refused. Needs the ACL **edit:changelog**.

**clear_changelog *host***  
Remove every entry of the changelog.  
This needs more than the ACL **clear:changelog**: the config parameter
**allow_changelog_clearing** has to allow it (see **otpme**(7)). It is
true by default, but where no value is found at all, clearing is
refused. OTPme asks the token you are signed in with first, then the
object.

## Policy Management

A *policy* is the name of a policy, not a path. It is looked for in the
site of the host. Which policies there are, and what each of them does,
is in **otpme-policy**(1).

Four types do something on a host: **logintimes** says when somebody may
log in here, **forcetoken** which token they have to use,
**autodisable** switches the host off after a time, and **authonaction**
asks whoever changes something here to authenticate for it again.

A **defaultpolicies** policy is taken as well, because it fits every
object in the tree, but nothing reads it on a host: what gives a new
host its policies is such a policy on the unit or the site above it.

A policy on the host runs at every login to it. A policy on a role runs
only where that role is assigned to the host and holds the token that is
logging in — a restriction on a role the token does not reach this host
through says nothing about this host.

Attaching and detaching ask before they change anything; the global
option **-f** skips the question.

**add_policy *host* *policy***  
Attach a policy to the host.  
A policy has a list of object types it is for; one that does not name
**host** is refused. So is a second policy of a type that allows only
one per object.  
Needs the ACL **assign:policy**.

**remove_policy *host* *policy***  
Remove a policy from the host.  
Needs the ACL **remove:policy**, and that one verbatim: a plain
**remove** does not cover it. Detaching a policy takes away what it
enforces, so it must not be cheaper than attaching one.

**list_policies \[**--return-type** *TYPE*\] \[**--policy-types** *t1,t2*\] *host***  
List the policies attached to the host. Use **--return-type** to select
the attribute returned (**name**, **read_oid**, **full_oid**, **uuid**).
Use **--policy-types** to list only policies of the given types; these
are policy types, not policy names.  
Needs the ACL **view:policies**.

## ACL Management

An ACL says what somebody may do with this host. The somebody is a role
or a token, never a user.

What the three forms **acl**, **+acl** and **++acl** mean, and which
ACLs exist, is under **ACLs** in **otpme**(7).

A command that changes something asks first; the global option **-f**
skips the question.

**add_acl *host* *owner_type* *owner* *acl*\[:*value*\]\[,*acl*\[:*value*\]\]**  
Give a role or a token one or more ACLs on this host.  
*owner_type* is **role** or **token**, and *owner* the path of that role
or token. An ACL may carry a value, for example **view:tokens**, and
several are separated by commas.  
Needs the ACL **add:acl**.

**del_acl *host* *acl*\[,*acl*\]**  
Take those ACLs away again.  
Here an *acl* is the whole entry, owner and all, the way **list_acls**
prints it: **role:berlin/sw-admins:view**.  
Needs the ACL **delete:acl**.

**list_acls *host***  
Show the ACLs that lie on this host, i.e. who may do what with it. Needs
the ACL **view:acl**.

**enable_acl_inheritance *host***  
Let the host inherit the default ACLs of the unit above it. It does not
by default.

Only default ACLs are inherited. An ordinary ACL on the unit never is.

Moving the host into another unit then takes away the default ACLs of
the old unit and applies those of the new one. While inheritance is off,
a move leaves the ACLs of the host as they are.

A move by somebody who does not hold **add:acl** and **delete:acl** on
the host leaves its ACLs alone as well, and says so. Otherwise moving an
object into a unit would be a way of handing yourself the default ACLs
of that unit.

Needs the ACL **enable:acl_inheritance**.

**disable_acl_inheritance *host***  
Stop inheriting them. Only the ACLs on the host itself count from then
on. Needs the ACL **disable:acl_inheritance**.

## Configuration

A config parameter is looked for on the host, then on the units above
it, then on the site. The first value found is the one that applies, and
the realm holds none. A site can turn that around for a parameter it
names in **force_site_config_parameters,** and then its own value wins
over the host and its units (see **otpme**(7)).

Which parameters a host takes is in **CONFIG PARAMETERS** below.

**config \[**-d**\] \[**-a**\] *host* *parameter* \[*value*\]**  
Set a parameter on the host.

**-d**  
Remove the parameter from the host, or with a value only that one value
from a list. It is not set back to a default: what applies afterwards is
whatever the unit or the site says.

**-a**  
Append the value to a parameter that holds a list, instead of replacing
what is there.

The ACL is per parameter, **set:config:***parameter*. Removing a
parameter that is not registered any more, which is what a rename or a
dropped feature leaves behind, is for admins only.

**show_config *host* \[*parameter*\]**  
The parameters set on the host itself, or only the one named. Nothing is
shown for a parameter that the host gets from a unit or from the site.

**get_config *host* *parameter***  
What the parameter comes to for this host, once the host, its units and
its site have been looked at. So this answers what applies, where
**show_config** answers what was set here.

**description *host* \[*description*\]**  
Set the description. Without one OTPme asks and offers the current text
for editing.

**info \[**--language** *LANG*\] *host* \[*info*\]**  
Set free-form info text. If *info* is omitted, the current info text is
opened in the editor named by the **EDITOR** environment variable.  
Without **--language** the text is the administrator's own note, which
no user is ever shown. A text can be written for a language as well, for
the places that show such a text to a user; nothing shows the info of a
host, so for a host it stays a note either way.

**dump_info \[**--language** *LANG*\] *host***  
Write one of those texts to stdout, for reading it with something other
than the editor.  
**--language** picks which one; without it you get the note of the
administrator. A language the host has no text for gives nothing and is
not an error.

## Export and Cleanup

Both write to stdout. There is no import on this page: reading an export
back in is **otpme-tool import,** see **otpme-tool**(1).

**remove_orphans** asks before it changes anything; the global option
**-f** skips the question.

**export \[**--password** *password*\] *host***  
Write the whole object of the host to stdout, as JSON.

Without **--password** it is written as it is, in clear. With one, a key
is derived from that password and the object is encrypted with it; the
salt goes into the output, so the password is all you need to read it
back.

What a host holds are references by UUID — its tokens, its roles, its
sync users and groups — so an export says something only in the realm it
came from. It carries the certificate and the public key of the host,
and no private key: that one never leaves the machine.

Needs the ACL **export**.

**remove_orphans *host***  
Remove what the host still points at although it is gone.

On a host that is its ACLs, its policies, the tokens and roles added to
it, and the users and groups it syncs. A token that is gone takes the
login interfaces and the SSH options that were stored with it.

The join node and the join token stay. Both keep a note of what they
pointed at so they can still be shown, and they say what happened, not
what is allowed.

It shows everything it found and asks once for all of it. It asks
nothing and changes nothing when it finds nothing.

Needs the ACL **remove:orphans**.

# OPTIONS

Every option belongs to one command and is described with that command
above. A short option means what that command makes of it.

Global options work with every command, see **otpme**(1).

# CONFIG PARAMETERS

Each parameter is described with the thing it is about: **vlans** under
**VLAN Assignment**, **allow_confd_jobs**, **allow_inventory** and
**inventory_site** under **Configuration Jobs and Inventory**,
**auto_sign** under **Token and Role Assignment**, and
**allow_changelog_clearing** under **Object Changelog**.

A host also carries the settings its own daemons read:
**socket_backlog** and **max_decompressed_size** always,
**backupd_max_conn** where it takes backups, and **httpd_workers**,
**httpd_socket_uri**, **httpd_ssl_workers** and **httpd_ssl_socket_uri**
where it serves the SSO portal.

What each of them does is in **otpme**(7).

# EXAMPLES

The examples use the site **berlin** of the realm **example.org** and a
notebook called **notebook1**.

## Taking a machine into the realm

**otpme-host add notebook1**  
Create the host object. It prints the JOTP, which is the one-time
password the machine joins with.

**otpme-tool join --jotp 12345678**  
Run on the machine itself. It gets its certificate and its keys, and a
LOTP for leaving is printed. See **otpme-tool**(1).

**otpme-host show notebook1**  
What the realm holds about it now: its unit, its tokens and roles, its
sync users and groups, and whether logins are limited.

## Who may log in there

**otpme-host add_role notebook1 office-staff**  
Everybody in the role may log in here, and the users the role syncs are
copied to the machine.

**otpme-host add_token notebook1 alice/login**  
One token on top of that, for somebody the role does not cover.

**otpme-host add_token -i ssh notebook1 bob/ssh**  
bob gets in over SSH and not at the console.

**otpme-host list_users notebook1**  
Who that comes to, for the tokens the host holds itself.

## An SSH key with one job

**otpme-host add_token notebook1 backup/ssh 'command="/usr/local/bin/backup",no-pty,from="10.0.0.5"'**  
The key may run that one command, from that one address, and gets no
shell.

**otpme-host get_ssh_authorized_keys notebook1 backup**  
The line sshd will be handed for that user.

## The port the machine hangs on

**otpme-host mac notebook1 00:11:22:33:44:55**  
The address the switch reports when nobody has logged in yet.

**otpme-accessgroup add_host lan notebook1**  
MAB needs this: the access group the request is answered for has to hold
the host. See **otpme-accessgroup**(1).

**otpme-vlan add_host office-vlan notebook1**  
The VLAN the machine is answered with. See **otpme-vlan**(1).

## What the machine gets from the realm

**otpme-host add_sync_user notebook1 alice**  
Sync her user object even if she never logs in here, so the machine can
resolve her as the owner of a file.

**otpme-host add_dynamic_group notebook1 plugdev**  
Everybody who logs in here is put into that local group for the session.

**otpme-host disable_sync_by_login_token notebook1**  
Sync every user and token of the site instead of only the ones that can
log in.

## Jobs and inventory

**otpme-host config notebook1 allow_confd_jobs role\|example.org/berlin/sw-admins**  
Who may send a configuration job to this machine. Nothing is allowed
until somebody is named.

**otpme-deploy add --host notebook1 --arg packages=htop sw_mgmt install**  
Install a package there. The job is signed, and the machine only takes
it from a signer of type **sw_mgmt**. See **otpme-deploy**(1).

**otpme-inventory packages notebook1**  
What it has installed. Reading it needs **allow_inventory**, see
**otpme-inventory**(1).

## When it leaves

**otpme-host enable_jotp_rejoin notebook1**  
Print the new JOTP to whoever leaves the realm, so the machine can come
back without an admin login.

**otpme-host del notebook1**  
Delete the object. The certificate is revoked, the roles and access
groups that name the host let it go, and the object goes to the trash.

# FILES

On a node:

*/var/lib/otpme/*  
The objects of the realm. A host lives in the unit it was created in,
**hosts** unless something else was said.

On the machine itself:

*/etc/otpme/otpme.conf*  
Its own config file. **VALID_LOGIN_USERS**, **DENY_LOGIN_USERS**,
**ALLOW_DYNAMIC_GROUPS**, **DENY_DYNAMIC_GROUPS** and the
**FORCE\_**\***\_SIGNERS** options are read here and nowhere else, see
**otpme.conf**(5).

*/etc/otpme/ssl/*  
Its certificate and keys: **cert.pem** with **key.pem** for TLS,
**hostkey.pem** for the key pair the realm holds the public half of,
**ca.pem** for the chain and *realm***-***site***.pem** for the site.

*/etc/otpme/signers/*type/**  
The signers of the machine, one directory per signer type, as
**otpme-tool add_signer** writes them. The ones a user added for
themselves are in *\~/.otpme/signers/*.

*/var/cache/otpme/ssh/authorized_keys/*user/authorized_keys**  
The SSH keys of that user, as sshd gets them through
**otpme-get-authorized-keys**. Written by **hostd** from the tokens the
host holds.

*/var/cache/otpme/offline/*user_uuid/**  
The tokens the machine can check while it cannot reach the realm, one
directory per user.

*/var/cache/otpme/nsscache/*  
**passwd**, **group** and **shadow** of the synced users and groups,
which is what the machine resolves them from.

# SEE ALSO

**otpme**(1), **otpme**(7), **otpme-acls**(7), **otpme.conf**(5),
**pam_otpme**(8), **otpme-tool**(1), **otpme-node**(1),
**otpme-token**(1), **otpme-role**(1), **otpme-accessgroup**(1),
**otpme-vlan**(1), **otpme-policy**(1), **otpme-deploy**(1),
**otpme-inventory**(1), **otpme-shell**(1), **otpme-trash**(1),
**otpme-ca**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2026 the2nd. License: GPLv3
