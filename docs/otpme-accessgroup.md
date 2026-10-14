# NAME

otpme-accessgroup - say who may use a service, and how its sessions work

# SYNOPSIS

**otpme-accessgroup** *command* \[*options*\] \[*accessgroup*\]

# DESCRIPTION

An access group answers one question: who may use this service.

Every client has one — a RADIUS client, an LDAP client, an OIDC client
of the SSO portal (see **otpme-client**(1)). When a login arrives there,
the access group of that client says whether the token is let in. What
is in the group gets in: a token that was added to it, every token of a
role that was added to it, and, for a switch port that is opened without
anybody logging in, a host or a device.

It answers a second question as well, and that one is about the service
and not about the people: whether a login creates a session and how long
that session lives, how many sessions a user may have at the same time,
and how many failed logins lock a user out of this service. So two
groups with the same tokens still differ: a VPN that holds a session for
a day and a management interface that asks again every time.

An access group lives in the **accessgroups** unit of a site, and the
nodes of that site are what answers logins with it. A host gets one
single access group, the **REALM** group of its own site, because that
is where it reads which login interfaces a token may use.

Every site is created with five groups of its own, see **THE GROUPS A
SITE BRINGS**.

For the bigger picture — what a client is, what a role is, how a login
runs — see **otpme**(7).

# COMMANDS

## Access Group Management

**add *accessgroup***  
Create an access group. It is created in the **accessgroups** unit of
your site; a path puts it into another unit, and **move** takes it there
afterwards.  
A name is lower case. Upper case is for the groups a site brings with
it, and a name that is one of theirs is taken as that group.  
Needs the ACL **add:accessgroup** on the unit it is created in, not on
the group — there is none yet.

**del \[**--no-trash**\] *accessgroup***  
Delete an access group. It goes to the trash, from where
**otpme-trash**(1) can bring it back; **--no-trash** deletes it right
away.  
What points at the group is named in the question first: the groups it
hangs under, its own child groups and child sessions, the clients that
use it and the tokens in it. Then the parent groups let it go and the
clients that used it are left without one — a client without an access
group lets nobody in.  
Needs the ACL **delete:object** on the group, or **delete:accessgroup**
on the unit it sits in.  
A group a site brings with it cannot be deleted.

**show \[**-a**\] \[**-z** *N*\] \[**--fields** *F1,F2*\] \[**--limit** *N*\] \[**--policy-limit** *N*\] \[**--sort-by** *field*\] \[**--reverse**\] \[**--raw**\] \[**--csv**\] \[**--csv-sep** *sep*\] \[*accessgroup*\]**  
Without a group: a table of all of them, with their child groups, the
failed logins they allow, whether they sign the SOTP, their sessions and
timeouts, their child sessions and their policies.

**-a**  
Also the groups you may only look at, not just the ones you may change.

**-z *N***  
How many groups to print.

**--fields *F1,F2***  
Print these columns and no others, in the order they are named. The
names are the ones in the header of the table.  
A name with a **+** in front is added to the columns that are shown
anyway, and one with a **-** is left out of them. The two cannot be
mixed with a plain list.  
Three columns are not in the table unless they are asked for: **roles**,
**tokens** and **inherit**. The first two are what is assigned to the
group itself — a token that only reaches it through a parent group is in
the column of that parent, and a disabled one is marked **(D)**. They
cost a query per group, which is why a list of groups does not pay for
them:

    otpme-accessgroup show --fields +roles,+tokens

**--limit *N*, **--policy-limit** *N***  
How many items to print per group, and the same for the policies alone.

**--sort-by *field*, **--reverse****  
Which column to sort by, and the other way round.

**--raw, **--csv**, **--csv-sep** *sep***  
For reading with something other than your eyes: **--raw** leaves the
header and the borders out, **--csv** prints one row per line with **;**
between the columns, and **--csv-sep** uses another separator.

A column you may not see says **-**. Which ACL opens which column is the
**view:** ACL of that value, and the **edit:**, **enable:** or
**remove:** ACL of it does as well — whoever may set a thing may read
it.  
With a group named, this prints the object itself instead of a table
row: one value per line, from its sessions and timeouts to its
checksums. A reference to an object that is gone is printed as the bare
UUID, which is how **remove_orphans** has something to find.

**list \[**-a**\] \[**--attribute** *attribute*\] \[*regex*\]**  
List the group names, and with a regex only those that match it. You get
the groups you may change; **-a** adds those you may only look at.  
**--attribute** matches the regex against that attribute instead of the
name: **list --attribute max_fail 3** lists the groups that allow three
failed logins. A value that is not text has to be spelled out — **\***
matches none of it.

**enable *accessgroup***  
Enable a disabled access group.

**disable *accessgroup***  
Disable an access group without deleting it. Nobody is let in through a
disabled group, and it is left out where groups are walked: a disabled
parent passes nothing on, and a disabled child is not reached.  
A user that was given **otpme-user enable_disabled_login** gets in all
the same, which is what keeps an administrator from locking themselves
out (see **otpme-user**(1)).

**rename *accessgroup* *new_name***  
Rename an access group.  
The clients that name it follow the rename, because a client holds the
group and not its name. A group a site brings with it cannot be renamed.

**move \[**--keep-acls**\] *accessgroup* *unit***  
Move the group into another unit. Its ACLs move with it: the default
ACLs of the old unit are taken away and those of the new one are
applied. **--keep-acls** leaves the ACLs of the group as they are.

**touch *accessgroup***  
Re-index the object to fix potential index problems.

## Token and Role Assignment

A token is named by its path, *user***/***token*. A role is named by its
name, which is looked for in the site of the access group, or as
*site***/***role* to take one from another site of the realm.

**add_token \[**--skip-portal-token**\] *accessgroup* *token_path* \[*token_options*\]**  
Let this token use the service.  
With SOTP signing enabled the sign public key of the token's user is
copied into the access group, see **SOTP SIGNING**.  
If the token is the SSO token of a site's portal (its name is that
site's **default_sso_token_name**), the tokens the portal manages for
the user — security keys, passkeys, tiqr phones and authenticator apps
added on its settings page — are added as well, after a confirmation.
**--skip-portal-token** adds only the given token.  
*token_options* are SSH **authorized_keys** options for the key of this
token, written as they stand in such a line: comma separated, and a
value may be quoted, as in **command="/usr/bin/x",no-pty**. Only the
options the token type allows are kept, the rest is dropped when the
file is written, with a warning in the log; **otpme-host**(1) lists
them.  
One group is asked for them: the **REALM** group of a site, when a host
of that site writes its **authorized_keys** and its logins are not
limited (see **limit_logins** in **otpme-host**(1)), because that is
where such a host takes the tokens of that group. On any other access
group they are kept with the assignment and nothing reads them. They are
not in **show_config** either, only in **export**.  
Needs the ACL **add:token**.

**remove_token \[**--skip-portal-token**\] *accessgroup* *token_path***  
Take the token away from the group. A UUID is taken as well, which is
how a reference to a token that is gone is cleared out.  
The sign public key of the user goes with their last token in this
group, and not before: a user with another token in it keeps it, and
OTPme says so.  
If the token is the SSO token of a portal, the tokens the portal manages
for the user are removed as well, after a confirmation;
**--skip-portal-token** removes only the given token.  
Needs the ACL **remove:token**.

**list_tokens \[**--return-type** *TYPE*\] \[**--token-types** *t1,t2*\] *accessgroup***  
List the tokens assigned to the group, by their path. Disabled tokens
are listed too.  
**--return-type** selects what to print instead (**name**, **read_oid**,
**full_oid**, **uuid**) and **--token-types** lists only tokens of the
given types.  
The tokens of the roles are not in this list, see **list_roles**.  
Needs the ACL **view:tokens**.

**add_role *accessgroup* *role***  
Add a role to the group. Every token of the role, and of the roles
inside it, may then use the service.  
This is the way to give a whole group of people a new service: the role
is already filled, so the service is one command.  
A group with forced SOTP signing takes no role, see **SOTP SIGNING**.  
Needs the ACL **add:role**.

**remove_role *accessgroup* *role***  
Remove a role from the group. A UUID is taken as well, which is how a
reference to a role that is gone is cleared out.  
Needs the ACL **remove:role**.

**list_roles *accessgroup***  
List the names of the roles assigned to the group.  
Needs the ACL **view:roles**.

## Host and Device Assignment

A host or a device in an access group is for a switch port that is
opened without anybody logging in: the switch asks with the MAC address,
and the access group of the client the switch is says whether that
machine is let in (MAC Authentication Bypass). A host is a machine of
the realm, a device is one that is not — a printer, a camera — see
**otpme-host**(1) and **otpme-device**(1).

Hosts and devices are not passed down to child groups. Tokens and roles
are, see **CHILD GROUPS**.

A site can have every new host or device put into a group by itself,
with **hosts_accessgroup** and **devices_accessgroup**. Setting those
needs **add:host** on the named group, because what follows are hosts
added to it without anybody being asked again (see **otpme**(7)).

**add_host *accessgroup* *host***  
Add a host to the group. The host is looked for in the site of the
group, or written as *site***/***host* to take one from another site of
the realm. Needs the ACL **add:host**.

**remove_host *accessgroup* *host***  
Remove the host again. Needs the ACL **remove:host**.

**list_hosts *accessgroup***  
List the hosts in the group. Needs the ACL **view:hosts**.

**add_device *accessgroup* *device***  
Add a device to the group. Needs the ACL **add:device**.

**remove_device *accessgroup* *device***  
Remove the device again. A UUID is taken as well. Needs the ACL
**remove:device**.

**list_devices *accessgroup***  
List the devices in the group. Needs the ACL **view:devices**.

## Sessions

What a session is and what it costs is under **SESSIONS** below. A time
is written with a unit: **30m**, **8h**, **1D**, **1W**, **1M**.

**enable_sessions *accessgroup***  
Let a login to this group create a session.  
Off by default, and the **MGMT** group cannot have it on.  
Needs the ACL **enable:sessions**.

**disable_sessions *accessgroup***  
Make every request authenticate by itself again.  
The **REALM** group cannot have it off.  
Needs the ACL **disable:sessions**.

**timeout *accessgroup* \[*time*\]**  
How long a session of this group lives, counted from the login. Default
**1800** seconds.  
**0** means it does not run out by itself. It cannot be set below the
unused timeout.  
Needs the ACL **edit:session_timeout**.

**unused_timeout *accessgroup* \[*time*\]**  
How long a session lives that nobody uses. Default **300** seconds.  
It cannot be set above the session timeout, and a value above it is read
as the session timeout.  
Needs the ACL **edit:unused_session_timeout**.

**max_sessions *accessgroup* \[*count*\]**  
How many sessions one token of one user may have in this group at the
same time. Default **0**, which is as many as they like.  
What happens when the number is reached is under **SESSIONS**.  
Needs the ACL **edit:max_sessions**.

**relogin_timeout *accessgroup* \[*time*\]**  
How long a session is safe from being thrown out to make room for a new
one. Default **0**, which is not at all.  
It does nothing on its own — it is read when **max_sessions** is
reached, see **SESSIONS**.  
Needs the ACL **edit:relogin_timeout**.

**enable_timeout_pass_on *accessgroup***  
Give the child sessions of this group its own timeouts instead of
theirs.  
Needs the ACL **enable:timeout_pass_on**.

**disable_timeout_pass_on *accessgroup***  
Let every child session keep the timeouts of its own group.  
Needs the ACL **disable:timeout_pass_on**.

**add_child_session *accessgroup* *accessgroup***  
Create a session for that group as well whenever a session is created
here.  
Needs the ACL **add:child_session**.

**remove_child_session *accessgroup* *accessgroup***  
Stop creating one. Sessions that exist are not touched.  
Needs the ACL **remove:child_session**.

## Failed Logins

**max_fail *accessgroup* \[*count*\]**  
How many failed logins lock a user out of this group. Default **5**.  
**0** does not lock anybody out, and nothing is counted at all.  
Needs the ACL **edit:max_fail**.

**max_fail_reset *accessgroup* \[*time*\]**  
After how long without another failed login the lock is lifted and the
counter thrown away. Default **0**, which never.  
Needs the ACL **edit:max_fail_reset**.

## Child Groups

**add_child_group *accessgroup* *child_group***  
Put a group under this one. The tokens and roles of this group may then
use the child group as well, see **CHILD GROUPS**.  
A group has one parent at most, and a group cannot be its own child.  
Needs the ACL **add:child_group** on this group, and **add:token** or
**add:role** on the child: whoever may hand access to the child this way
has to be allowed to hand it over directly.

**remove_child_group *accessgroup* *child_group***  
Take the group out from under this one.  
Needs the ACL **remove:child_group**.

## SOTP Signing

What this is for is under **SOTP SIGNING** below.

**enable_sotp_signing *accessgroup***  
Require clients to sign the SOTP they authenticate with.  
The keys of the users that have one are copied into the access group;
the users without one are named and do not sign.  
Needs the ACL **enable:sotp_signing**.

**disable_sotp_signing *accessgroup***  
Do no longer require it. The copied keys are removed with it, and forced
signing is switched off.  
Needs the ACL **disable:sotp_signing**.

**enable_force_sotp_signing *accessgroup***  
Require every user to sign, not only those whose key the group holds.  
Only with signing enabled, no role in the group, and a key for every
user that has a token in it — otherwise those users are named and
nothing is changed.  
A token that only gets in through a parent group has no key here, so it
can no longer authenticate.  
Needs the ACL **enable:force_sotp_signing**.

**disable_force_sotp_signing *accessgroup***  
Require it only from the users whose key the group holds. Signing stays
on and the keys are kept.  
Needs the ACL **disable:force_sotp_signing**.

**update_sign_public_keys *accessgroup* \[*username*\]**  
Take over the keys the users have now, all of them or only *username*.  
Keys without a token in the group are removed with it. A user without a
key is named; asked for one user, that is an error.  
Needs SOTP signing to be enabled, and the ACL **edit:sign_public_keys**.

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

**changelog *accessgroup***  
Show the changelog of the access group. Needs the ACL
**view:changelog**.

**edit_changelog *accessgroup* *entry_id* *comment***  
Set the comment of that entry, or replace the one it has. Needs the ACL
**edit:changelog**.

**del_changelog *accessgroup* *entry_id***  
Remove the comment of that entry. The entry itself stays, and an entry
without a comment is refused. Needs the ACL **edit:changelog**.

**clear_changelog *accessgroup***  
Remove every entry of the changelog.  
This needs more than the ACL **clear:changelog**: the config parameter
**allow_changelog_clearing** has to allow it (see **otpme**(7)). It is
true by default, but where no value is found at all, clearing is
refused. OTPme asks the token you are signed in with first, then the
object.

## Policy Management

A *policy* is the name of a policy, not a path. It is looked for in the
site of the access group. Which policies there are, and what each of
them does, is in **otpme-policy**(1).

Attaching and detaching ask before they change anything; the global
option **-f** skips the question.

**add_policy *accessgroup* *policy***  
Attach a policy to the access group.  
A policy has a list of object types it is for; one that does not name
**accessgroup** is refused. So is a second policy of a type that allows
only one per object.  
Needs the ACL **assign:policy**.

**remove_policy *accessgroup* *policy***  
Remove a policy from the access group.  
Needs the ACL **remove:policy**, and that one verbatim: a plain
**remove** does not cover it. Detaching a policy takes away what it
enforces, so it must not be cheaper than attaching one.

**list_policies \[**--return-type** *TYPE*\] \[**--policy-types** *t1,t2*\] *accessgroup***  
List the policies attached to the access group. Use **--return-type** to
select the attribute returned (**name**, **read_oid**, **full_oid**,
**uuid**). Use **--policy-types** to list only policies of the given
types; these are policy types, not policy names.  
Needs the ACL **view:policies**.

## ACL Management

An ACL says what somebody may do with this access group. The somebody is
a role or a token, never a user.

What the three forms **acl**, **+acl** and **++acl** mean, and which
ACLs exist, is under **ACLs** in **otpme**(7).

A command that changes something asks first; the global option **-f**
skips the question.

**add_acl *accessgroup* *owner_type* *owner* *acl*\[:*value*\]\[,*acl*\[:*value*\]\]**  
Give a role or a token one or more ACLs on this group.  
*owner_type* is **role** or **token**, and *owner* the path of that role
or token. An ACL may carry a value, for example **view:tokens**, and
several are separated by commas.  
Needs the ACL **add:acl**.

**del_acl *accessgroup* *acl*\[,*acl*\]**  
Take those ACLs away again.  
Here an *acl* is the whole entry, owner and all, the way **list_acls**
prints it: **role:berlin/sw-admins:view**.  
Needs the ACL **delete:acl**.

**list_acls *accessgroup***  
Show the ACLs that lie on this group, i.e. who may do what with it.
Needs the ACL **view:acl**.

**enable_acl_inheritance *accessgroup***  
Let the group inherit the default ACLs of the unit above it. It does not
by default.

Only default ACLs are inherited. An ordinary ACL on the unit never is.

Moving the group into another unit then takes away the default ACLs of
the old unit and applies those of the new one. While inheritance is off,
a move leaves the ACLs of the group as they are.

Needs the ACL **enable:acl_inheritance**.

**disable_acl_inheritance *accessgroup***  
Stop inheriting them. Only the ACLs on the group itself count from then
on. Needs the ACL **disable:acl_inheritance**.

## Configuration

A config parameter is looked for on the access group, then on the units
above it, then on the site. The first value found is the one that
applies, and the realm holds none. A site can turn that around for a
parameter it names in **force_site_config_parameters,** and then its own
value wins (see **otpme**(7)).

Which parameters an access group takes is in **CONFIG PARAMETERS**
below.

**config \[**-d**\] \[**-a**\] *accessgroup* *parameter* \[*value*\]**  
Set a parameter on the group.

**-d**  
Remove the parameter from the group, or with a value only that one value
from a list. It is not set back to a default: what applies afterwards is
whatever the unit or the site says.

**-a**  
Append the value to a parameter that holds a list, instead of replacing
what is there.

The ACL is per parameter, **set:config:***parameter*.

**show_config *accessgroup* \[*parameter*\]**  
The config parameters set on the group itself, or only the one named.  
Nothing is shown for a parameter that the group gets from a unit or from
the site, and nothing for one whose ACL **view:config:***parameter* you
do not hold. The settings of the group — its sessions, its timeouts, its
tokens and roles — are not config parameters: **show** and **export**
are where those are.

**get_config *accessgroup* *parameter***  
What the parameter comes to for this group, once the group, its units
and its site have been looked at. So this answers what applies, where
**show_config** answers what was set here.  
Needs the ACL **view:config:***parameter*, the same one that opens it in
**show_config**.

**description *accessgroup* \[*description*\]**  
Set the description. Without one OTPme asks and offers the current text
for editing.

**info \[**--language** *LANG*\] *accessgroup* \[*info*\]**  
Set free-form info text. If *info* is omitted, the current info text is
opened in the editor named by the **EDITOR** environment variable.  
Without **--language** the text is the administrator's own note about
the object, which no user is ever shown. A text written for a language
is one for the users of that language.  
For the **SSO** group such a text is the recovery mail: first line the
subject, then an empty line, then the body, with **{user_name}**,
**{minutes}** (how long the link is valid) and **{reset_url}** filled
in. Any other placeholder is refused, here and not when somebody needs
that mail. Which text is sent follows the language of the user, see
**otpme**(7).

**dump_info \[**--language** *LANG*\] *accessgroup***  
Write one of those texts to stdout, for reading it with something other
than the editor.  
**--language** picks which one; without it you get the note of the
administrator. A language the group has no text for gives nothing and is
not an error.

**add_extension *accessgroup* *extension***  
Add an LDAP extension to the group, which is what gives it LDAP object
classes and attributes.

**remove_extension *accessgroup* *extension***  
Remove the extension again, with the attributes that came with it.

**add_attribute *accessgroup* *attribute*=*value***  
Add an LDAP attribute to the group.

**del_attribute *accessgroup* *attribute*=*value***  
Remove an LDAP attribute.

**add_object_class *accessgroup* *class***  
Add an LDAP object class.

**del_object_class *accessgroup* *class***  
Remove an LDAP object class.

## Export and Cleanup

Both write to stdout. There is no import on this page: reading an export
back in is **otpme-tool import,** see **otpme-tool**(1).

**remove_orphans** asks before it changes anything; the global option
**-f** skips the question.

**export \[**--password** *password*\] *accessgroup***  
Write the whole object of the group to stdout, as JSON.  
Without **--password** it is written as it is, in clear. With one, a key
is derived from that password and the object is encrypted with it; the
salt goes into the output, so the password is all you need to read it
back.  
What a group holds are references by UUID — its tokens, its roles, its
hosts, its devices, its child groups — so an export says something only
in the realm it came from. It carries the sign public keys it holds as
well.  
Needs the ACL **export**.

**remove_orphans *accessgroup***  
Remove what the group still points at although it is gone.  
On an access group that is its ACLs, its policies, the tokens, roles,
hosts and devices in it, and its child groups. A token that is gone
takes the options stored with it.  
It shows everything it found and asks once for all of it. It asks
nothing and changes nothing when it finds nothing.  
Needs the ACL **remove:orphans**.

# SESSIONS

Without sessions every request authenticates by itself. That is what you
want for a management interface, and it is what makes an OTP an OTP: it
is used once.

With sessions the first login creates one, and for as long as it lives
the same password or OTP is accepted again. That is for the services
that ask over and over with what they were given once — an IMAP server
that opens a connection per folder, a VPN that reauthenticates. The
price is that an OTP is no longer used only once: it works as long as
the session lives.

Two timeouts end a session: **timeout** counts from the login, and
**unused_timeout** counts from the last time it was used. The second
cannot be larger than the first.

**max_sessions** is counted per user and token, in this group. When a
new login would go past it, the oldest sessions are thrown out to make
room — but only those that are older than **relogin_timeout**. Where
that does not free enough, the login fails. So the two together say what
happens to somebody who logs in again and again: with
**relogin_timeout** at **0** the oldest session is always the one that
goes, and with a value set the sessions of the last few minutes are safe
and the login is refused instead.

A **child session** is created along with the session of this group, for
every group named with **add_child_session**, and for the child sessions
of those groups in turn. It is created with the password hash of the
login that created it, so the other service takes the same password.
That is what it is for, and it matters most with a one time password: a
mail client that logs in at **imap** with an OTP gets a session for
**smtp** along with it, and sends its mail with that same OTP.

A child session is created whether or not the token would be let into
that group by itself, and whether or not that group has sessions
enabled. So name the groups that belong to this one.

With **timeout_pass_on** the child sessions get the timeouts of the
group the login happened at, instead of their own. Without it each of
them lives by the timeouts of its own group.

The sessions that exist are listed and deleted with **otpme-session**,
and what an agent holds on one machine with **otpme-tool show_sessions**
(see **otpme-tool**(1)).

# FAILED LOGINS

Failed logins are counted per user and per access group, and what is
counted is the wrong password: a client that asks again and again with
the same wrong one counts once.

When the count reaches **max_fail**, the user is locked out of this
group — and only out of this one. The other services go on working,
which is the point of counting per group.

**max_fail 0** counts nothing and locks nobody out.

A lock is lifted in two ways: **max_fail_reset** seconds without another
failed login lift it and throw the counters away, and **otpme-user
unblock *user* \[*accessgroup*\]** lifts it now, for one group or for
all of them (see **otpme-user**(1)). With **max_fail_reset** at **0**
only the second one does.

A user whose **failed_pass_history** is smaller than the **max_fail** of
a group keeps as many as that group needs, and says so in the log: a
counter that is thrown away too early would be a lock that never comes.

# CHILD GROUPS

A group under another group is a group its tokens and roles reach as
well.

A child group is not a child session: a child group says who gets in, a
child session says what a login creates (see **SESSIONS**). The two are
set separately, and the groups a site brings have child groups only —
**MGMT** and **LDAP** under **REALM**, and no child sessions anywhere.

So the way in is inherited downwards: a token in the parent gets into
the child, and into the children of the child. That is why
**add_child_group** asks for **add:token** or **add:role** on the child
— it hands out the same access those two hand out, and must not be
cheaper.

Hosts and devices are not inherited. A host in a parent group does not
get the child group.

A group has one parent at most. A disabled group passes nothing on and
is not reached.

The **SSO** group is the exception, and it is one on purpose. The groups
of the applications hang under it, and the portal reads them to decide
which applications it shows. So for a login to one of those groups the
parents are not walked, and a token that is only in **SSO** is turned
away: it may log in to the portal, and the applications are each their
own decision. See **otpme**(7).

# SOTP SIGNING

With SOTP signing enabled a client has to sign the SOTP it authenticates
with, using the sign private key of its user. The access group keeps a
copy of the sign public key of every user that has a token in it, and
the node verifies the signature against that copy.

What that buys: a user of another site cannot be let in with an SOTP
alone. Whoever controls the nodes of that site can produce a valid SOTP
and can change the public key of the user there, but cannot touch the
copy inside this access group.

Only daemons that can handle a signed SOTP ask for it, which today means
**mgmtd** — the daemon these commands talk to. A file share has a
signing flag of its own, see **otpme-share**(1).

Signing is required from a user only if the group holds their key. A
user without one authenticates as before, which is what makes it
possible to switch signing on while the users are still getting their
keys. **enable_force_sotp_signing** drops that exception: every user has
to sign, so a user without a key cannot authenticate at all. A group
with forced signing takes no roles, because a role would bring in tokens
whose users have no key here.

A user who generates a new key pair loses access until
**update_sign_public_keys** takes the new key over. That is on purpose:
updating the copy by itself would hand the site of the user the very
control the copy takes away from it.

# THE GROUPS A SITE BRINGS

Every site is created with five access groups of its own. They cannot be
renamed or deleted, and their names are upper case.

**REALM**  
The group a login to the realm goes through. It is also the one group a
host reads, for the login interfaces of its tokens.  
It has sessions, with a timeout of **1M** and an unused timeout of
**3W**, at most **3** sessions per token and a relogin timeout of
**1s**. Sessions cannot be switched off for it.  
**MGMT** and **LDAP** are its child groups, so a token that may log in
to the realm can use the management interface and LDAP as well.

**MGMT**  
The group for these commands, i.e. for **mgmtd**.  
It has no sessions and cannot have any: every management command
authenticates by itself.

**LDAP**  
The group of the LDAP service, **ldapd**.  
It has sessions (**1D**, unused **1D**), at most **3** per token,
relogin timeout **1m**.

**SSO**  
The group of the SSO portal.  
It has sessions (**1M**, unused **1M**), at most **3** per token,
relogin timeout **1m**, and it passes its timeouts on to its child
sessions.  
The groups of the applications hang under it, see **CHILD GROUPS**. Its
info text is the recovery mail, see **info** above.

**JOIN**  
The group a machine joins the realm through, i.e. for **joind**.  
It has no sessions.

# VLANS

An access group decides whether a token, host or device gets access at
all. Which network it is put into is decided separately, by a VLAN (see
**otpme-vlan**(1)). Both are answered in the same RADIUS reply, but
nothing ties them together: membership in an access group grants no
VLAN, and a VLAN grants no access.

An access group is not assigned a VLAN and cannot be a member of one. To
give the objects of an access group a VLAN, put them, or a role they are
in, into the VLAN:

> **otpme-vlan add_role *vlan* *role***

# OPTIONS

Every option belongs to one command and is described with that command
above.

Global options work with every command, see **otpme**(1).

# CONFIG PARAMETERS

An access group takes these:

**auto_sign (bool)**  
Sign the assignment when a token is added to this group. There is no
**--sign** on **add_token** here, so this parameter, or the one of the
token you are signed in with, is what decides.  
Default: false

**changelog (bool)**  
Whether the commands on this group are written to its changelog.  
Default: true

**allow_changelog_clearing (bool)**  
Whether the changelog of this group may be cleared, see
**clear_changelog** above.  
Default: true

What each of them does, and how a parameter is resolved, is in
**otpme**(7).

# EXAMPLES

The examples use the site **berlin** of the realm **example.org**.

## A service for a group of people

**otpme-accessgroup add vpn**  
Create the group for the VPN.

**otpme-accessgroup description vpn "Who may use the VPN"**  
Say what it is for.

**otpme-accessgroup add_role vpn employees**  
Everybody in that role may use the VPN. One command per service from
then on, because the role is already filled.

**otpme-accessgroup add_token vpn alice/totp**  
One token on top of that, for somebody the role does not cover.

**otpme-client access_group vpn_gateway vpn**  
Hand the group to the client the VPN gateway is — without this the group
lets nobody in anywhere.

**otpme-accessgroup list_tokens vpn**  
The tokens that were added by hand. The tokens of the roles are not in
it.

## Sessions for a service that asks again and again

**otpme-accessgroup enable_sessions imap**  
Let a login create a session.

**otpme-accessgroup timeout imap 8h**  
It lives eight hours.

**otpme-accessgroup unused_timeout imap 30m**  
Half an hour of nobody using it ends it earlier.

**otpme-accessgroup max_sessions imap 3**  
Three at a time per token.

**otpme-accessgroup relogin_timeout imap 5m**  
A session of the last five minutes is not thrown out to make room; the
fourth login is refused instead.

## Locking out after failed logins

**otpme-accessgroup max_fail vpn 3**  
Three wrong passwords lock the user out of the VPN, and out of nothing
else.

**otpme-accessgroup max_fail_reset vpn 10m**  
Ten quiet minutes lift the lock.

**otpme-accessgroup max_fail mgmt_readonly 0**  
Count nothing here.

## Services that belong together

**otpme-accessgroup add_child_group wlan wlan_guests**  
Whoever may use **wlan** may use **wlan_guests** too.

**otpme-accessgroup add_child_session imap smtp**  
A session for **imap** brings one for **smtp**.

**otpme-accessgroup enable_timeout_pass_on imap**  
And those sessions live by the timeouts of **imap**.

## A port without a login

**otpme-accessgroup add_host printer_net client1**  
Let that machine onto the port by its MAC address.

**otpme-accessgroup add_device printer_net printer1**  
The same for a machine that is not a host of the realm.

## Making a service ask for a signed SOTP

**otpme-accessgroup enable_sotp_signing mgmt**  
The users that have a sign key sign from now on; the others are named
and go on as before.

**otpme-accessgroup update_sign_public_keys mgmt alice**  
alice made a new key pair: take it over, or she stays out.

**otpme-accessgroup enable_force_sotp_signing mgmt**  
Now everybody signs, and a user without a key cannot authenticate any
more.

## Who may change the group

**otpme-accessgroup add_acl vpn role it-support add:token,remove:token,view:tokens**  
The role may hand out and take away the VPN, and see who has it, and
nothing else about the group.

# SEE ALSO

**otpme**(1), **otpme**(7), **otpme-acls**(7), **otpme-client**(1),
**otpme-scope**(1), **otpme-role**(1), **otpme-token**(1),
**otpme-user**(1), **otpme-host**(1), **otpme-device**(1),
**otpme-vlan**(1), **otpme-share**(1), **otpme-policy**(1),
**otpme-tool**(1), **otpme-trash**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2026 the2nd. License: GPLv3
