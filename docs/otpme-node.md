# NAME

otpme-node - manage OTPme nodes

# SYNOPSIS

**otpme-node** *command* \[*options*\] \[*node*\]

# DESCRIPTION

**otpme-node** manages the nodes of a realm: the machines that run it.

A node is not a host. A host syncs the users and tokens it needs and
asks a node whenever a password or an OTP has to be checked. A node
holds every object of its site and answers that question itself. It runs
the daemons the realm is made of: **mgmtd** for these commands,
**authd** for logins, **syncd** for the hosts and the other sites,
**clusterd** for the nodes of its own site, **joind** for machines that
join, and **ldapd**, **ssod**, **fsd**, **racd**, **idled**, **httpd**
and **backupd** for what the site serves. See **otpme-host**(1) for a
host and **otpme**(7) for the daemons.

A node has no sync configuration. A host is told which users and tokens
it gets; a node of the site gets all of them, the admin user, the
templates and the internal users included.

One node of a site holds the master role. These commands run on that
node and nowhere else: a connection to another node is answered with
"Please connect to master node". See **The Master Role** below.

The first node of a realm or of a site is made together with the realm
or the site: **otpme-realm init** and **otpme-site add** create the node
they run on (see **otpme-realm**(1) and **otpme-site**(1)). Every other
node is made with **add** here, and the machine itself joins with
**otpme-tool join --host-type node** (see **otpme-tool**(1)).

# COMMANDS

## Node Management

**add *node***  
Create a node. The machine itself need not exist yet: this is the object
a join with a JOTP looks for. The name has to be unique in the realm: no
node and no host of any site may have it already. It prints the JOTP.  
There is no **rename**. A node is found by the name it joined with,
which is also the name in its certificate, so a machine that is renamed
leaves the realm and joins again.

**del \[**--no-trash**\] *node***  
Delete a node. It goes to the trash, from where **otpme-trash**(1) can
bring it back; **--no-trash** deletes it right away.

The certificate of the node is revoked and the sessions it holds are
deleted. The node that holds the master role is refused: let the role
move first, see **The Master Role** below.

The shares and pools that name this node keep their reference. Nothing
clears it here, so look with **find_shares** and **find_pools** first,
or run **remove_orphans** on those objects afterwards.

The machine itself is not asked anything. A node that is still joined
should leave the realm first, with **otpme-tool leave**.

**show \[**-a**\] \[**-z** *N*\] \[**--fields** *F1,F2*\] \[**--limit** *N*\] \[**--token-limit** *N*\] \[**--role-limit** *N*\] \[**--policy-limit** *N*\] \[**--sort-by** *field*\] \[**--reverse**\] \[**--raw**\] \[**--csv**\] \[**--csv-sep** *sep*\] \[*node*\]**  
Show the nodes, with their tokens, roles and policies. Without a node
you get all of them.

**-a**  
Also the nodes you may only look at, not just the ones you may change.

**-z *N***  
How many nodes to print.

**--fields *F1,F2***  
Print these columns and no others. The names are the ones in the header
of the table.

**--limit *N***  
How many of each kind to print per node: tokens, roles, policies.

**--token-limit *N*, **--role-limit** *N*, **--policy-limit** *N***  
The same for one of them, where the others should stay as they are.

**--sort-by *field*, **--reverse****  
Which column to sort by, and the other way round.

**--raw, **--csv**, **--csv-sep** *sep***  
For reading with something other than your eyes: **--raw** leaves the
header and the borders out, **--csv** prints one row per line with **;**
between the columns, and **--csv-sep** uses another separator.

**list \[**-a**\] \[**--attribute** *attribute*\] \[*regex*\]**  
List the node names, and with a regex only those that match it. You get
the nodes you may change; **-a** adds those you may only look at.  
**--attribute** matches the regex against that attribute instead of the
name: **list --attribute enabled True** lists the nodes that are
enabled. A value that is not text has to be spelled out — **\*** matches
none of it.

**enable \[**--offline**\] *node***  
Enable a disabled node.  
Nothing is asked of the node itself: while it was disabled it asked the
master once a second whether it still is, and it starts its own services
again as soon as it is not. **--offline** is taken so a node can be
enabled the way it is disabled, and it changes nothing.  
The node then syncs like one that has just joined, which includes the
deletions it missed while it was away.

**disable \[**--offline**\] *node***  
Disable a node without deleting it.

This asks first, and then tells the node to stop answering requests
before the object is disabled — otherwise it would still be handing out
logins while the question was on screen. An aborted disable starts its
services again.

**--offline** leaves the node alone, for one that cannot be reached any
more.

A disabled node takes no part in the election, votes that it cannot be
master, and refuses the connections of its peers. It does not count
towards the quorum either, because the quorum is counted from the
enabled nodes.

The node that holds the master role is refused.

**move \[**--keep-acls**\] *node* *unit***  
Move the node into another unit. Its ACLs move with it: the default ACLs
of the old unit are taken away and those of the new one are applied.
**--keep-acls** leaves the ACLs of the node as they are.

**touch *node***  
Re-index the object to fix potential index problems.

## Token and Role Assignment

A token is named by its path, *user***/***token*. A role is named by its
name, which is looked for in the site of the node, or as
*site***/***role* to take one from another site of the realm.

**add_token \[**-i** *interfaces*\] \[**--no-auto-sign**\] \[**--sign** **--tags** *tag1,tag2*\] *node* *token_path* \[*token_options*\]**  
Let this token log in to the node.

**-i *interfaces***  
Only these login interfaces, comma separated: **gui**, **tty**, **ssh**.
With a leading **-** the interface is the one that is not allowed, as in
**-gui**, and the two forms cannot be mixed.

*token_options*  
SSH options for the key of this token, written as they stand in an
**authorized_keys** line: comma separated, and a value may be quoted, as
in **command="/usr/bin/x --a,--b",no-pty**.  
They are for an SSH token, and only the options that token allows;
anything else is dropped when the **authorized_keys** file is written,
with a warning in the log. The list is in **otpme-host**(1).

**--sign, **--tags** *tag1,tag2***  
Sign the token for this assignment. The signature carries the user and
this node, and the interfaces and options where they were given, so it
says what the token was allowed to do here. How signing works, and what
a signer makes of the tags, is in **otpme-role**(1). A token that cannot
be signed with **--sign** is an error.

**--no-auto-sign**  
Do not sign, whatever the **auto_sign** of the node or the **autosign**
setting of your own user says.

A token that is already assigned, with other interfaces or options, is
not added twice: OTPme asks whether to change what it has.

**remove_token \[**--keep-sign**\] *node* *token_path***  
Take the token away from the node. The signature for this assignment is
removed with it; **--keep-sign** leaves it in place.

**list_tokens \[**--return-type** *TYPE*\] \[**--token-types** *t1,t2*\] *node***  
List the tokens assigned to the node. Use **--return-type** to select
the attribute returned (**name**, **read_oid**, **full_oid**, **uuid**)
and **--token-types** to limit the listing to the given token types.

**add_role *node* *role***  
Add a role to the node. Its tokens may then log in here, with the
interfaces and options they were given in the role. The dynamic groups
of the role, and of the roles in it, are added to everybody who logs in
here.

**remove_role *node* *role***  
Remove a role from the node. A UUID is taken as well, which is how a
reference to a role that is gone is cleared out.

**list_roles *node***  
List the names of the roles assigned to the node.

## Login Control

Who may log in to a node is decided by the tokens and roles it holds,
see **Token and Role Assignment** above. A node limits logins from the
moment it is made: only what is assigned to it gets in. Opened up, every
token of the REALM access group may log in, and the assignments then
only say what else a token gets there.

**limit_logins *node***  
Only let the tokens and roles assigned to this node log in. This is how
a node starts.

**unlimit_logins *node***  
Let every token of the REALM access group log in. The assignments stay
as they are, with their login interfaces and options.

On top of that the machine itself can refuse a user, in its config file
and not in the realm. **VALID_LOGIN_USERS** is a list, and a user not in
it may not log in. **DENY_LOGIN_USERS** is a list of users that may not
log in whatever else says so, and it is asked first. An entry is a user
name, or *name*:*uuid* to name the user you mean and no other. Both are
checked for an interactive login and for an SSH key, see
**otpme.conf**(5).

## User and Group Listing

**--return-type** picks what these print: **name** (the default),
**read_oid**, **full_oid** or **uuid**.

**list_users \[**--return-type** *TYPE*\] *node***  
The users who own a token assigned to the node. Only the tokens the node
holds itself count here, not the ones it gets through a role.

**list_dynamic_groups *node***  
The dynamic groups of the node, with those of the roles it is in.

## Where this node is used

A command that starts with **list\_** answers what the node holds. One
that starts with **find\_** answers the other question: where the node
itself is named.

**--return-type** works as above, and a name from another site is
printed as *site***/***name*. Disabled objects are listed as well, so
something that is only switched off is not mistaken for something that
is gone. Each of these needs its own ACL, **find:shares** for
**find_shares** and **find:pools** for **find_pools**.

**find_shares \[**--return-type** *TYPE*\] *node***  
The shares this node serves. A share that names no node at all is served
by every node of its site, so an empty answer does not mean the node
serves nothing. See **otpme-share**(1).

**find_pools \[**--return-type** *TYPE*\] *node***  
The pools this node serves. A pool hands out shares of its own, and it
names its nodes the same way a share does, see **otpme-pool**(1).

## Dynamic Groups

A dynamic group is a local group of the machine, such as **plugdev** or
**audio**. Whoever logs in through the PAM module is put into it for
that session, without being a member of anything in the realm. Two sides
are added together: the groups of the node and of the roles the node is
in, and the groups of the login token and of the roles it is in. The
roles in those roles count too, however deep they go. A group that does
not exist on the machine is skipped, with a warning in the log.

**add_dynamic_group *node* *group***  
Add a dynamic group to the node. Everybody who logs in here gets it.

**remove_dynamic_group *node* *group***  
Remove a dynamic group from the node.

The machine has the last word, in its config file.
**ALLOW_DYNAMIC_GROUPS** set to **False** switches dynamic groups off
altogether; as a list it allows only the groups it names.
**DENY_DYNAMIC_GROUPS** names the groups never to add. Deny is asked
first. See **otpme.conf**(5).

## The Master Role

One node of a site holds the master role. It is the node these commands
run on, the node every tree object of the site is written to, and —
where the site has one — the node that holds the floating IP of the
site. It also runs the two daemons that go with the role: **idled**,
which tells the agents of the logged-in users what happens, and
**racd**, where the two ends of a remote access session meet (see
**otpme-shell**(1)). A node that gives the role up stops them, and the
node that takes it starts them.

The role is not configured, it is elected, over and over, by the nodes
of the site. Each of them answers with a vote, and the highest vote
wins:

> The vote of a node is the time it was last in sync with the master. So
> of two nodes that can hold the role, the one that is more nearly up to
> date gets it.
>
> A node that has never synced votes one minus the time its daemons
> started, a number below zero. Of several such nodes the one that has
> been up longest wins, which is how the first master of a fresh realm
> is found.
>
> A vote of zero says "I cannot be master". A disabled node says it, and
> so does a node that has not finished its first sync — a node that was
> just enabled again says it for as long as that takes.
>
> Where there is no master and the nodes answer with different data
> revisions, only the nodes with the highest revision stand.
>
> A node that holds the role and votes 0 gives it up. It has answered,
> and the answer was no.
>
> A node that holds the role and does not answer at all keeps it, for as
> long as the node check still counts it as up. Every node runs the
> election for itself, so one connection that did not get through would
> be enough for the node that asked to make itself master — and it would
> keep the role from then on, because winning stamps its own sync file
> and that is the highest vote there is. So no vote from the master is
> read as a moment of silence, not as a node that went away.
>
> A node that really goes away stops answering the node check and is
> dropped from the nodes that count. The election then runs as it always
> does and the site gets a new master.

The election needs a quorum, and so does the site: without one **ldapd**
is stopped and management is refused. The quorum is half the enabled
nodes of the site, unless a number is set with **otpme-cluster
required_votes**. **otpme-cluster status** shows where the cluster
stands, and **otpme-cluster master_failover** hands the role to another
node; both are in **otpme-cluster**(1).

A vote script lets you take part in that decision. It runs on the node
when its vote is asked for, and it says whether this node is willing to
hold the role — because the storage it needs is not mounted, for one, or
because it is the node in the other room.

Every site is given one to start from, **scripts/node_vote_script.sh**,
which does nothing but exit 0. Write what the node should answer into it
with **otpme-script edit**, or add a script of your own, see
**otpme-script**(1).

**vote_script *node* *vote_script* \[*script_options*\]**  
Set the vote script of the node.

*vote_script* is the path of a script in the site of the node, as
**otpme-script list** prints it, e.g. **scripts/node_vote_script.sh**,
and that script has to grant you **assign**. What follows it are the
options it is called with, as one argument. An empty name takes the
script away.

Exit code 0 keeps the ordinary vote of the node. Anything else votes 0,
so the node does not become master while the script says no.

A script that cannot be found, or that fails to run at all, votes 1.
That is a real vote and lower than any sync time, so such a node is the
last choice rather than no choice, and it says so in the log.

Needs the ACL **edit:vote_script**.

**enable_vote_script *node***  
Start asking the script. Needs the ACL **enable:vote_script**.

**disable_vote_script *node***  
Stop asking it. The script stays set, and the node votes as it would
without one. Needs the ACL **disable:vote_script**.

## Realm Join and Leave

A machine joins the realm with **otpme-tool join --host-type node** and
leaves it with **otpme-tool leave** (see **otpme-tool**(1)). Either an
admin logs in for it, or the machine uses a one-time password.

The JOTP is the one for joining. **add** makes one, and **enable_jotp**
prints it. It is gone once the node has joined, and a LOTP for leaving
is made in its place. Leaving the realm revokes the certificate of the
node, drops its public key and makes a new JOTP, so the machine can come
back.

**enable_jotp *node***  
Allow joining with the JOTP, and print it. It is allowed by default.

**disable_jotp *node***  
Refuse the JOTP. A join then needs an admin login.

**enable_lotp *node***  
Allow leaving with the LOTP, and print it. It is allowed by default.

**disable_lotp *node***  
Refuse the LOTP. Leaving then needs an admin login.

**enable_jotp_rejoin *node***  
Print the new JOTP to the machine that is leaving. Whoever leaves the
realm can then join again without an admin login. It is off by default.

**disable_jotp_rejoin *node***  
Keep the new JOTP to yourself.

The JOTP and the LOTP are shown by **show** and by **export** to whoever
holds the ACL **view:jotp** or **view:lotp**.

## Certificates and Keys

A node gets a certificate and a key pair of its own when it joins. The
certificate is for TLS, and it is how a daemon knows which node is at
the other end of a connection.

The key pair is how a node proves that it is that node. **syncd**,
**clusterd** and **backupd** ask for it before they answer anything:
both ends sign a challenge of the other, and each checks the answer
against the public key on the node object in the tree. A challenge older
than five seconds is refused. The private half never leaves the machine,
it stays in **hostkey.pem**; the public half is what the commands below
show and set.

The same key is the SSH host key of a remote shell — the node vouches
for it, and the other end holds that against the public key here (see
**otpme-shell**(1)).

The certificate is renewed on the machine itself, with **otpme-tool
renew_cert**. The certificate request is made there, with the key of the
node; this side only signs it.

**dump_cert *node***  
Print the certificate of the node.

**dump_ca_chain *node***  
Print the CA certificates above it, up to the CA of the site.

**get_public_key *node***  
Print the public key of the node.

**public_key *node* \[*public_key*\]**  
Replace the public key of the node. Without the key as an argument you
are asked to paste it; an empty answer takes the key away.  
The join sets this, so there is normally no reason to touch it.

## SSH

**get_ssh_authorized_keys *node* \[*user*\]**  
Ask the realm which SSH keys this node lets in. With a user the lines
come as sshd reads them; without one the keys of every user come, each
line with the user name in front. A key that needs a signature and does
not have one is left out.

On the machine itself sshd does not read this. It calls
**otpme-get-authorized-keys *username*,** which answers from the file
**hostd** keeps:

> **AuthorizedKeysCommand /usr/local/bin/otpme-get-authorized-keys**  
> **AuthorizedKeysCommandUser root**

The keys are synced before the answer, or the first login of a token
that was just added would be refused. Not more often than every 30
seconds, though: sshd runs the command on every login attempt, and
anybody who reaches port 22 can make one. A sync per attempt would let
whoever knocks at the door decide how often this node syncs.

## Object Changelog

Every change to the object writes an entry: who made it, when, and what
was done. A change can carry a comment of its own, through the global
option **--changelog**.

Unless the **changelog** config parameter says otherwise. It is read
along the cascade of the node, and nothing is written where it is off —
not for that node, and not for the ones below a unit that switched it
off. Without any value anywhere it is on.

An *entry_id* is the number the listing shows in front of an entry,
counted from 0.

Only the comment of an entry can be changed or removed. What was done
and by whom stays as it is.

A command that changes something asks first; the global option **-f**
skips the question.

**changelog *node***  
Show the changelog of the node. Needs the ACL **view:changelog**.

**edit_changelog *node* *entry_id* *comment***  
Set the comment of that entry, or replace the one it has. Needs the ACL
**edit:changelog**.

**del_changelog *node* *entry_id***  
Remove the comment of that entry. The entry itself stays, and an entry
without a comment is refused. Needs the ACL **edit:changelog**.

**clear_changelog *node***  
Remove every entry of the changelog.  
This needs more than the ACL **clear:changelog**: the config parameter
**allow_changelog_clearing** has to allow it (see **otpme**(7)). It is
true by default, but where no value is found at all, clearing is
refused. OTPme asks the token you are signed in with first, then the
object.

## Policy Management

A *policy* is the name of a policy, not a path. It is looked for in the
site of the node. Which policies there are, and what each of them does,
is in **otpme-policy**(1).

Four types do something on a node: **logintimes** says when somebody may
log in here, **forcetoken** which token they have to use,
**autodisable** switches the node off after a time, and **authonaction**
asks whoever changes something here to authenticate for it again.

A **defaultpolicies** policy is taken as well, because it fits every
object in the tree, but nothing reads it on a node: what gives a new
node its policies is such a policy on the unit or the site above it.

A policy on the node runs at every login to it. A policy on a role runs
only where that role is assigned to the node and holds the token that is
logging in — a restriction on a role the token does not reach this node
through says nothing about this node.

Attaching and detaching ask before they change anything; the global
option **-f** skips the question.

**add_policy *node* *policy***  
Attach a policy to the node.  
A policy has a list of object types it is for; one that does not name
**node** is refused. So is a second policy of a type that allows only
one per object.  
Needs the ACL **assign:policy**.

**remove_policy *node* *policy***  
Remove a policy from the node.  
Needs the ACL **remove:policy**, and that one verbatim: a plain
**remove** does not cover it. Detaching a policy takes away what it
enforces, so it must not be cheaper than attaching one.

**list_policies \[**--return-type** *TYPE*\] \[**--policy-types** *t1,t2*\] *node***  
List the policies attached to the node. Use **--return-type** to select
the attribute returned (**name**, **read_oid**, **full_oid**, **uuid**).
Use **--policy-types** to list only policies of the given types; these
are policy types, not policy names.  
Needs the ACL **view:policies**.

## ACL Management

An ACL says what somebody may do with this node. The somebody is a role
or a token, never a user.

What the three forms **acl**, **+acl** and **++acl** mean, and which
ACLs exist, is under **ACLs** in **otpme**(7).

A command that changes something asks first; the global option **-f**
skips the question.

**add_acl *node* *owner_type* *owner* *acl*\[:*value*\]\[,*acl*\[:*value*\]\]**  
Give a role or a token one or more ACLs on this node.  
*owner_type* is **role** or **token**, and *owner* the path of that role
or token. An ACL may carry a value, for example **view:tokens**, and
several are separated by commas.  
Needs the ACL **add:acl**.

**del_acl *node* *acl*\[,*acl*\]**  
Take those ACLs away again.  
Here an *acl* is the whole entry, owner and all, the way **list_acls**
prints it: **role:berlin/sw-admins:view**.  
Needs the ACL **delete:acl**.

**list_acls *node***  
Show the ACLs that lie on this node, i.e. who may do what with it. Needs
the ACL **view:acl**.

**enable_acl_inheritance *node***  
Let the node inherit the default ACLs of the unit above it. It does not
by default.

Only default ACLs are inherited. An ordinary ACL on the unit never is.

Moving the node into another unit then takes away the default ACLs of
the old unit and applies those of the new one. While inheritance is off,
a move leaves the ACLs of the node as they are.

A move by somebody who does not hold **add:acl** and **delete:acl** on
the node leaves its ACLs alone as well, and says so. Otherwise moving an
object into a unit would be a way of handing yourself the default ACLs
of that unit.

Needs the ACL **enable:acl_inheritance**.

**disable_acl_inheritance *node***  
Stop inheriting them. Only the ACLs on the node itself count from then
on. Needs the ACL **disable:acl_inheritance**.

## Configuration

A config parameter is looked for on the node, then on the units above
it, then on the site. The first value found is the one that applies, and
the realm holds none. A site can turn that around for a parameter it
names in **force_site_config_parameters,** and then its own value wins
over the node and its units (see **otpme**(7)).

Which parameters a node takes is in **CONFIG PARAMETERS** below.

**config \[**-d**\] \[**-a**\] *node* *parameter* \[*value*\]**  
Set a parameter on the node.

**-d**  
Remove the parameter from the node, or with a value only that one value
from a list. It is not set back to a default: what applies afterwards is
whatever the unit or the site says.

**-a**  
Append the value to a parameter that holds a list, instead of replacing
what is there.

The ACL is per parameter, **set:config:***parameter*. Removing a
parameter that is not registered any more, which is what a rename or a
dropped feature leaves behind, is for admins only.

**show_config *node* \[*parameter*\]**  
The parameters set on the node itself, or only the one named. Nothing is
shown for a parameter that the node gets from a unit or from the site.

**get_config *node* *parameter***  
What the parameter comes to for this node, once the node, its units and
its site have been looked at. So this answers what applies, where
**show_config** answers what was set here.

**description *node* \[*description*\]**  
Set the description. Without one OTPme asks and offers the current text
for editing.

**info \[**--language** *LANG*\] *node* \[*info*\]**  
Set free-form info text. If *info* is omitted, the current info text is
opened in the editor named by the **EDITOR** environment variable.  
Without **--language** the text is the administrator's own note, which
no user is ever shown. A text can be written for a language as well, for
the places that show such a text to a user; nothing shows the info of a
node, so for a node it stays a note either way.

**dump_info \[**--language** *LANG*\] *node***  
Write one of those texts to stdout, for reading it with something other
than the editor.  
**--language** picks which one; without it you get the note of the
administrator. A language the node has no text for gives nothing and is
not an error.

## Export and Cleanup

Both write to stdout. There is no import on this page: reading an export
back in is **otpme-tool import,** see **otpme-tool**(1).

**remove_orphans** asks before it changes anything; the global option
**-f** skips the question.

**export \[**--password** *password*\] *node***  
Write the whole object of the node to stdout, as JSON.

Without **--password** it is written as it is, in clear. With one, a key
is derived from that password and the object is encrypted with it; the
salt goes into the output, so the password is all you need to read it
back.

What a node holds are references by UUID — its tokens, its roles, its
vote script — so an export says something only in the realm it came
from. It carries the certificate and the public key of the node, and no
private key: that one never leaves the machine.

Needs the ACL **export**.

**remove_orphans *node***  
Remove what the node still points at although it is gone.

On a node that is its ACLs, its policies, the tokens and roles added to
it, and its vote script. A token that is gone takes the login interfaces
and the SSH options that were stored with it. A vote script that is gone
is worth clearing: the node votes 1 at every election while it is named
and missing.

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

A node carries three kinds of parameter. What each of them does is in
**otpme**(7).

The one that is only a node's is **cluster_write_procs:** how many
processes this node uses to write its cluster journal to a peer. Zero
works it out from the cores. It can be set on a unit or on the site as
well, so a cluster of alike nodes is configured once.

Then the settings the daemons of the node read: **authd_workers**,
**authd_max_workers**, **authd_worker_threads**, **authd_idle_timeout**,
**ldapd_processes**, **ldap_cache**, **ldap_shared_cache**,
**ldap_shared_cache_time**, **httpd_workers**, **httpd_ssl_workers**,
**httpd_socket_uri**, **httpd_ssl_socket_uri**, **socket_backlog**,
**max_decompressed_size** and one **\***\_max_conn**** per daemon:
**mgmtd_max_conn**, **syncd_max_conn**, **joind_max_conn**,
**clusterd_max_conn**, **fsd_max_conn**, **racd_max_conn**,
**idled_max_conn**, **ssod_max_conn** and **backupd_max_conn**.

And the backup of the node. **add** writes a list of excludes to start
from, and switches the backup on where the unit or the site already says
so: **backup_enabled**, **backup_mode**, **backup_excludes**,
**backup_includes**, **backup_exclude_special**, **backup_server**,
**backup_time**, **backup_interval**, **backup_retry_interval**,
**backup_retry_count**, **backup_key**, **backup_repo_password** and the
report of a run, **backup_report_enabled**, **backup_report_mode**,
**backup_report_mail_from**, **backup_report_mail_to** with
**smtp_relay_server**, **smtp_relay_port**, **smtp_relay_starttls**,
**smtp_relay_auth**, **smtp_relay_username** and
**smtp_relay_password**. See **otpme-backup**(1).

The rest is shared with a host and described in **otpme-host**(1):
**allow_confd_jobs** and **allow_inventory** with **inventory_site**,
**auto_sign** for the tokens the node takes in, and **changelog** with
**allow_changelog_clearing**.

# EXAMPLES

The examples use the site **berlin** of the realm **example.org** and a
second node called **node2**.

## Taking a node into the realm

**otpme-node add node2**  
Create the node object. It prints the JOTP, which is the one-time
password the machine joins with.

**otpme-tool join --host-type node --jotp 12345678**  
Run on the machine itself. It gets its certificate and its keys, syncs
the site, and a LOTP for leaving is printed. See **otpme-tool**(1).

**otpme-cluster status**  
Where the cluster stands now: who is master, who is in sync, and whether
the site has a quorum.

## Who may log in there

**otpme-node add_role node2 sw-admins**  
Everybody in the role may log in here.

**otpme-node add_token node2 alice/login**  
One token on top of that, for somebody the role does not cover.

**otpme-node add_token -i ssh node2 bob/ssh**  
bob gets in over SSH and not at the console.

## The master role

**otpme-node vote_script node2 scripts/node_vote_script.sh**  
Ask that script whether this node is willing to be master. The one every
site is given exits 0, so edit it first.

**otpme-node enable_vote_script node2**  
Start asking it. A non-zero exit code now votes 0, and the node stays
out of the race.

**otpme-cluster master_failover --to node2**  
Hand the role over by hand.

## Taking a node out

**otpme-node find_shares node2**  
Which shares name this node, before anything is taken away.

**otpme-node disable node2**  
The node stops answering requests first, then the object is disabled.
Enabling it again syncs it like a node that has just joined.

**otpme-tool leave**  
Run on the machine itself. Its certificate is revoked and a new JOTP is
made, so it can come back.

**otpme-node del node2**  
Delete the object. The node that holds the master role is refused.

# FILES

On the node:

*/var/lib/otpme/*  
The objects of the realm: **tree/** for the sites, units, users, tokens
and the nodes themselves, **data/** for what they produce — jobs,
inventories, used OTPs, token counters — and **sessions/** and
**trash/**. A node lives in the unit it was created in, **nodes** unless
something else was said.

*/var/spool/otpme/node_sync_time*  
When this node was last in sync with the master. Its vote is read from
here, see **The Master Role** above.

*/var/spool/otpme/node_synced*  
Says that this node has synced with the master at all. Without it the
node serves nothing: **ldapd** is not started, and **mgmtd**, **authd**,
**joind**, **ssod**, **fsd**, **racd** and **idled** answer "Cluster not
ready". Only the daemons the node needs to catch up keep answering:
**hostd**, **syncd**, **clusterd** and **backupd**.

*/var/spool/otpme/new_node*  
Says that the next sync has to be the one of a node that joined, which
deletes what was removed while the node was away. Written by a join and
by an enable.

*/var/spool/otpme/cluster_out_journal/, */var/spool/otpme/cluster_in_journal/**  
What still has to go to the peers of this node, and what came from them
and is not written yet.

*/etc/otpme/otpme.conf*  
Its own config file. **VALID_LOGIN_USERS**, **DENY_LOGIN_USERS**,
**ALLOW_DYNAMIC_GROUPS** and **DENY_DYNAMIC_GROUPS** are read here and
nowhere else, see **otpme.conf**(5).

*/etc/otpme/ssl/*  
Its certificate and keys: **cert.pem** with **key.pem** for TLS,
**hostkey.pem** for the key pair the realm holds the public half of,
**ca.pem** for the chain and *realm***-***site***.pem** for the site.

*/var/cache/otpme/ssh/authorized_keys/*user/authorized_keys**  
The SSH keys of that user, as sshd gets them through
**otpme-get-authorized-keys**.

# SEE ALSO

**otpme**(1), **otpme**(7), **otpme-acls**(7), **otpme.conf**(5),
**pam_otpme**(8), **otpme-cluster**(1), **otpme-tool**(1),
**otpme-host**(1), **otpme-realm**(1), **otpme-site**(1),
**otpme-token**(1), **otpme-role**(1), **otpme-script**(1),
**otpme-share**(1), **otpme-pool**(1), **otpme-policy**(1),
**otpme-backup**(1), **otpme-shell**(1), **otpme-trash**(1),
**otpme-ca**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2026 the2nd. License: GPLv3
