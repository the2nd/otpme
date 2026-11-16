# NAME

otpme-policy - manage policies: password rules, login times, defaults
for new objects and more

# SYNOPSIS

**otpme-policy** \[**--type** *policy_type*\] *command* \[*options*\]
\[*policy*\]

# DESCRIPTION

**otpme-policy** adds, configures and removes policies. A policy is an
object in a unit. It does nothing until it is assigned to another
object, with **add_policy** of that object's command, e.g. **otpme-user
add_policy**. Then it acts at its moments: when a password is set, at a
login, when an object is added to a unit, before an action.

What a policy does depends on its type, see **POLICY TYPES**. An object
takes one policy of each type. A new site comes with a set of them, see
**What a new site has**.

# POLICY TYPES

The type is chosen when the policy is added (**--type**) and cannot be
changed. An object takes one policy of each type; a second one of the
same type is refused. What the settings of a type are is under **POLICY
TYPE DETAILS**.

**password**  
How good a password or PIN has to be. For user, token, host, node; a
token without one is checked with the one of its user.

**logintimes**  
When a login is allowed. For user, token, role, host, node, client,
accessgroup.

**autodisable**  
Disable the object it is assigned to after a time, or after it was
unused for that long. For every object type except the realm, policies,
scripts and passwords, and not for an object the realm or a site comes
with, e.g. the admin user. "Unused for" only where the object keeps its
last use: user, token, host, node, client, device, resolver, share.

**forcetoken**  
Which token types or pass types a login there must use. For role, host,
node, client, accessgroup.

**authonaction**  
Log in again before an action, e.g. changing a PIN. For every object
type.

**defaultunits**  
Which unit a new object goes to, for the objects a user adds. For user.

**defaultgroups**  
Which groups a new user joins, and their default group. For unit.

**defaultroles**  
Which roles the default token of a new user joins. For unit.

**defaultpolicies**  
Which policies a new object gets, per object type. For site, unit: the
unit or site the object is added to.

**idrange**  
Which uidNumber and gidNumber a new user or group gets. For site, unit.

**tokenacls**  
Which ACLs a new token gets, and the user and token that added it. For
user.

**objecttemplates**  
Which template a new user or host is made from. For unit.

## What a new site has

A site is created with these policies:

**auth_on_action**  
authonaction, on every object.

**password_strength**  
password, on every user, token, host and node.

**token_acls**  
tokenacls, on every user.

**default_units**  
defaultunits, on every user.

**id_range**  
idrange, on the site.

**default_policies**  
defaultpolicies, on the site and on every unit. It is what hands the
ones above to new objects.

**default_groups**, **default_roles**  
defaultgroups and defaultroles, on the unit **users**.

**object_templates**  
objecttemplates, on every unit.

**auto_disable_hour**, **\_day**, **\_week**, **\_month**, **\_year**  
autodisable, assigned to nothing.

**workhours_login**, **weekend_login**  
logintimes, assigned to nothing.

**force_token_otp**, **force_token_non_static**  
forcetoken, assigned to nothing.

# COMMANDS

## Policy Management

**add *policy***  
Create a policy. The type is given with **--type**, e.g. **otpme-policy
--type password add pw-default**. See **POLICY TYPES** for the types.  
A policy goes to the unit **policies**, or to the one a **defaultunits**
policy of your user names. Name another unit as *unit*/*policy*. Needs
**add:policy**, or **add:policy:\<type\>**, on that unit.  
A new policy does nothing until it is assigned to an object, see
**Policy Assignment**.

**del** \[**--no-trash**\] *policy*  
Delete a policy. It goes to the trash, from where **otpme-trash**(1) can
bring it back with its assignments; **--no-trash** deletes it right
away.  
The question names every object the policy is assigned to; **-f**
deletes without asking. Needs **delete:object** on the policy, or
**delete:policy** (or **delete:policy:\<type\>**) on its unit.

**show** \[**-a**\] \[**-z** *N*\] \[**--fields** *F1,F2*\] \[**--limit** *N*\] \[**--policy-limit** *N*\] \[*policy*\]  
Without a policy, a table of all of them with their unit, type and
status; the options below are for that table. With a policy, its
settings: what the commands of its type set, see **POLICY TYPE
DETAILS**.

**-a**  
Also the policies you may only look at, not just the ones you may
change.

**-z *N***  
How many policies to print.

**--fields *F1,F2***  
Print these columns and no others. The names are the ones in the header
of the table: **policy**, **unit**, **type**, **status**, **policies**,
**inherit**, **description**.

**--limit *N*, **--policy-limit** *N***  
How many entries to print in the column **policies**, the policies
assigned to the policy itself. 5 by default, 30 when you show one
policy.

<!-- -->

**show_oid** \[**--full**\] *policy*  
Show the OID of the policy: **policy\|\<realm\>/\<site\>/\<name\>**.
With **--full** the full OID, which names the unit as well:
**policy\|\<realm\>/\<site\>/\<unit_path\>/\<name\>**.  
Needs the ACL **view_public:object**.

**show_uuid *policy***  
Show the UUID of the policy.  
Needs the ACL **view_public:object**.

<!-- -->

**list** \[*pattern*\]  
List the policy names, and with a pattern only those that match it, see
**SELECTING OBJECTS** in **otpme**(1).

**enable *policy***  
Enable a disabled policy.

**disable *policy***  
Disable a policy without deleting it. A disabled policy does nothing: it
stays assigned, but no check, default or ID range comes from it.  
A policy is never disabled by a time: it has no **auto_disable**, and an
auto-disable policy is not for policies.

**rename *policy* *new_name***  
Rename a policy. It asks first; **-f** does not. The assignments stay,
they hold the UUID.

**move** \[**--keep-acls**\] *policy* *unit*  
Move the policy into another unit. Needs **add:policy** on the new unit.
Its ACLs move with it: the default ACLs of the old unit are taken away
and those of the new one are applied. **--keep-acls** leaves them as
they are.

## Policy Configuration

What a policy does is set with the commands of its type, see **POLICY
TYPE DETAILS**. **config** sets the parameters every object has; for a
policy these are **changelog** and **allow_changelog_clearing**, see
**Object Changelog**.

**config** \[**-d**\] \[**-a**\] *policy* *parameter* \[*value*\]  
Set a parameter on the policy.

**-d**  
Remove the parameter from the policy, or with a value only that one
value from a list. It is not set back to a default: what applies
afterwards is whatever the unit or the site says.

**-a**  
Append the value to a parameter that holds a list, instead of replacing
what is there.

The ACL is per parameter, **set:config:\<parameter\>**.

**show_config *policy* \[*parameter*\]**  
The parameters set on the policy itself, or only the one named. Nothing
is shown for a parameter that the policy gets from a unit or from the
site.

**get_config *policy* *parameter***  
What the parameter comes to for this policy, once the policy, its units
and its site have been looked at. So this answers what applies, where
**show_config** answers what was set here.

**description *policy* \[*description*\]**  
Set the description. Without one OTPme asks and offers the current text
for editing. Needs **edit:description**.

**info** \[**--language** *LANG*\] *policy* \[*info*\]  
Set free-form info text. If *info* is omitted, the current info text is
opened in the editor named by the **EDITOR** environment variable. Needs
**edit:info**.  
Without **--language** the text is the administrator's own note. Nothing
shows the info of a policy to a user, so a text for a language stays a
note as well.

**dump_info** \[**--language** *LANG*\] *policy*  
Write one of those texts to stdout. **--language** picks which one;
without it you get the note of the administrator. Needs **view:info**.

## Policy Assignment

A policy can have policies assigned to it like any other object. They
act on the policy itself, not on the objects it is assigned to. Two
types can be assigned to a policy:

> -   **authonaction**: who changes the policy has to log in again
>     first.
>
> -   **autodisable**: the policy is disabled after the time set there,
>     and from then on does nothing.

A *child_policy* is the name of a policy, not a path. It is looked for
in the site of the policy it is assigned to.

Assigning and removing ask before they change anything; the global
option **-f** skips the question.

**add_policy *policy* *child_policy***  
Assign a policy to this policy. A type that is not for policies is
refused, and so is a second policy of a type that allows only one per
object.  
Needs the ACL **assign:policy**.

**remove_policy *policy* *child_policy***  
Remove a policy from this policy.  
Needs the ACL **remove:policy**, and that one verbatim: a plain
**remove** does not cover it. Removing a policy takes away what it
enforces, so it must not be cheaper than assigning one.

**list_policies** \[**--return-type** *TYPE*\] \[**--policy-types** *t1,t2*\] *policy*  
List the policies assigned to this policy, disabled ones too, marked
**(disabled)**. **--return-type** picks what is printed: **name** (the
default), **read_oid**, **full_oid** or **uuid**. **--policy-types**
lists only policies of these types; they are policy types, not policy
names.  
Needs the ACL **view:policies**.

## ACL Management

An ACL says what somebody may do with this policy. The somebody is a
role or a token, never a user.

What the three forms **acl**, **+acl** and **++acl** mean is under
**ACLs** in **otpme**(7). Tab completion after **add_acl** offers the
ACLs a policy knows, those of **policy** and those of its type.

A command that changes something asks first; the global option **-f**
skips the question.

**add_acl *policy* *owner_type* *owner* *acl*\[:*value*\]\[,*acl*\[:*value*\]\]**  
Give a role or a token one or more ACLs on this policy.  
*owner_type* is **role** or **token**. *owner* names it the way
**list_acls** prints it: a role as *site/name*, or by its name alone on
its own site; a token as *user/token*. An ACL can carry a value, for
example **view:policy_type**. To give several ACLs at once, separate
them with commas: **view:policy_type,view:status**.  
Needs the ACL **add:acl**.

**del_acl *policy* *acl*\[,*acl*\]**  
Take those ACLs away again.  
Here an *acl* is the whole entry, owner and all, the way **list_acls**
prints it: **role:berlin/pw-admins:view:policy_type**.  
Needs the ACL **delete:acl**.

**list_acls *policy***  
Show the ACLs that lie on this policy, i.e. who may do what with it.
Needs the ACL **view:acl**.

**enable_acl_inheritance *policy***  
Let a move of the policy swap its default ACLs: what the old unit handed
down is taken away, and what the new unit hands down is given. It does
not by default; a move then leaves the ACLs of the policy as they are.

Only a move asks this. A new policy gets the default ACLs of its unit,
and **add_acl -a** or **-r** on a unit reach it either way. A move with
**--keep-acls** leaves its ACLs alone all the same.

A move by somebody who does not hold **add:acl** and **delete:acl** on
the policy leaves its ACLs alone as well, and says so. Otherwise moving
an object into a unit would be a way of handing yourself the default
ACLs of that unit.

Needs the ACL **enable:acl_inheritance**.

**disable_acl_inheritance *policy***  
A move leaves the ACLs of the policy as they are again.  
Needs the ACL **disable:acl_inheritance**.

## Object Changelog

Every change to the object writes an entry: who made it, when, and what
was done. A change can carry a comment of its own, through the global
option **--changelog**.

Unless the **changelog** config parameter says otherwise. It is read
along the cascade of the policy, and nothing is written where it is off
— not for that policy, and not for the ones below a unit that switched
it off. Without any value anywhere it is on.

An *entry_id* is the number the listing shows in front of an entry,
counted from 0.

Only the comment of an entry can be changed or removed. What was done
and by whom stays as it is.

A command that changes something asks first; the global option **-f**
skips the question.

**changelog *policy***  
Show the changelog of the policy, one entry per line: its *entry_id*,
the time, who made the change and what was done, then a detail in round
brackets and the comment in square brackets where there are any. Needs
the ACL **view:changelog**.

**edit_changelog *policy* *entry_id* *comment***  
Set the comment of that entry, or replace the one it has. That writes an
entry of its own. Needs the ACL **edit:changelog**.

**del_changelog *policy* *entry_id***  
Remove the comment of that entry. The entry itself stays, and an entry
without a comment is refused. That writes an entry of its own. Needs the
ACL **edit:changelog**.

**clear_changelog *policy***  
Remove every entry of the changelog. Afterwards it holds one entry: that
it was cleared.  
This needs more than the ACL **clear:changelog**: the config parameter
**allow_changelog_clearing** has to allow it (see **otpme**(7)). It is
true by default, but where no value is found at all, clearing is
refused. A value set on the token you are signed in with counts first.
Without one, the value of the object counts, read along its cascade.

## Export and Cleanup

Both write to stdout. There is no import on this page: reading an export
back in is **otpme-tool import,** see **otpme-tool**(1).

**remove_orphans** asks before it changes anything; the global option
**-f** skips the question.

**export** \[**--password** *password*\] *policy*  
Write the whole object of the policy to stdout, as JSON.

Without **--password** it is written as it is, in clear. With one, a key
is derived from that password and the object is encrypted with it; the
salt goes into the output, so the password is all you need to read it
back.

What a policy names, the groups, roles, units, policies or templates of
its type, it names by UUID, so an export says something only in the
realm it came from.

Needs the ACL **export**.

**remove_orphans *policy***  
Remove what the policy still points at although it is gone.

On every policy that is its ACLs and the policies assigned to it. Its
type adds its own lists: the units of **defaultunits**, the roles of
**defaultroles**, the groups of **defaultgroups**, the policies of
**defaultpolicies**, the whitelist of **authonaction**, the templates of
**objecttemplates** and the dictionaries of **password**.

It shows everything it found and asks once for all of it. It asks
nothing and changes nothing when it finds nothing.

Needs the ACL **remove:orphans**.

# POLICY TYPE DETAILS

## Password Policy

Checks a password or a PIN when it is set: on a token, on a user, on a
host or node. A token without a password policy of its own is checked
with the one of its user.

A new policy asks for at least 8 characters with a number, an upper- and
a lowercase letter and a special character, a PIN of at least 4 digits,
and a strength score of at least 2 from the checker **spsc**. A PIN is
digits only. Which characters a password may contain at all is the
config parameter **password_allowed_chars** of the site, unit or user.

The **enable\_** and **disable\_** commands change at once; the others
ask first, and **-f** skips the question.

> **password_min_len *policy* *length***  
> **pin_min_len *policy* *length***  
> The shortest password, the shortest PIN. Needs
> **edit:password_min_len**, **edit:pin_min_len**.
>
> **enable_require_number**\|**\_upper**\|**\_lower**\|**\_special** *policy*  
> **disable_require_number**\|**\_upper**\|**\_lower**\|**\_special** *policy*  
> Whether a password needs a number, an uppercase letter, a lowercase
> letter, a special character. Needs **enable:number**,
> **disable:number**, and the same with **uppercase**, **lowercase**,
> **special**.
>
> **enable_strength_checker *policy***  
> **disable_strength_checker *policy***  
> Whether the strength of a password is scored on top of the rules
> above. Needs **enable:strength_checker**,
> **disable:strength_checker**.
>
> **strength_checker *policy* *checker***  
> Which checker scores it. **spsc** is the only one. Needs
> **edit:strength_checker**.
>
> **strength_checker_opts *policy* *options***  
> The options of the checker, as *name*=*value* separated by a
> semicolon, e.g. **"min_score=3;dict_order=en,de"**. Each call replaces
> all of them; what is not given falls back to its default. Needs
> **edit:strength_checker_opts**.
>
> **min_score**=*N*  
> The lowest score a password may have. A score runs from 0 to 10 and is
> about the years it takes to guess the password at a million tries a
> second. Default 2.
>
> **dict_order**=*d1*,*d2*  
> The dictionaries a password is looked up in, and in which order; see
> **otpme-dictionary**(1). Default none. A dictionary that is disabled
> or deleted is skipped. The **password_strength** policy of a site has
> all the dictionaries the site was created with.
>
> **recent_years_past**=*N*, **recent_years_future**=*N*  
> Years in a password that count as easy to guess, counted back and
> forward from this year. Default 150 and 10.
>
> **test** \[**--password** *password*\] \[**--pin** *pin*\] *policy*  
> Check a password or a PIN against the policy, without setting it. For
> a password it prints the score and whether it is strong enough.

## Login Times Policy

When a login is allowed. It is checked at every login, on the token, the
user and the access group, on the host, node or client, and on the roles
that let the token in there. An admin token is always let in. The time
is the local time of the node that checks the login.

A site has **workhours_login** (**\* 6-18 \* \* 1-5**, Monday to Friday
6:00 to 18:59) and **weekend_login** (**\* \* \* \* 6-7**), assigned to
nothing.

> **login_times *policy* *times***  
> When a login is allowed, like the time fields of **cron**(5): minute
> (0-59), hour (0-23), day of month (1-31), month (1-12), day of week
> (1-7, Monday is 1). A field is **\***, a number, a range like
> **8-17**, or a list of them like **1,3,5-7**. A range whose end is
> below its start goes round: **22-6** is 22:00 to 6:59. Several entries
> are separated by **\|**; a login is allowed if one of them matches,
> e.g. **"\* 8-17 \* \* 1-5\|\* 9-12 \* \* 6"**.  
> It asks first; **-f** does not. Needs **edit:login_times**.
>
> **test --object-type *type* --test-object *object* --token *token* *policy***  
> Check whether *token* may log in now, with the policy as if it were
> assigned to *object* of *type*. *object* is a name, for a token its
> path. All three are required.

## Auto-Disable Policy

Disables the object it is assigned to once its time is up: when the
object is loaded, and at the latest when the master node looks, every 5
minutes. The time counts from when the policy was assigned.

To enable such an object again takes **-f**, and the time starts anew.

A site has **auto_disable_hour**, **\_day**, **\_week**, **\_month** and
**\_year** (+1h, +1D, +1W, +1M, +1Y), assigned to nothing.

> **auto_disable** \[**-u**\] *policy* *time*  
> After how long, or when. A relative time has a leading **+**, e.g.
> **+30D** for 30 days; the units are **s**, **m**, **h**, **D**, **W**,
> **M** (30 days) and **Y** (365 days), see **otpme**(7). An absolute
> one is a date and a time, e.g. **"09:53 13.06.2027"** or **"2027-06-13
> 09:53"**.  
> With **-u** the time counts from the last use of the object instead,
> so it is disabled once it was unused for that long. That takes a
> relative time, and an object that keeps its last use, see **POLICY
> TYPES**; one that was never used counts from the assignment.  
> It asks first; **-f** does not. Needs **edit:auto_disable**.

## Force Token Policy

Which tokens may log in there. It is checked at every login on the role,
host, node, client or access group it is assigned to, for admin tokens
too. A link token is checked as the token it points to.

A token is let in when its type is in **force_token_types** (if that is
set) and its pass type in **force_pass_types** (if that is set). The
pass types are **otp** (hotp, totp, motp), **otp_push**, **tiqr**,
**smartcard** (fido2, u2f, passkey, yubikey_hmac, yubikey_piv),
**ssh_key**, **static** (password, and an ssh token used with a
password), and **script_otp** and **script_static**, which are the types
of the script tokens themselves.

A new policy has no token types and the pass types otp, otp_push, tiqr,
ssh_key and smartcard. A site has **force_token_otp** (otp, otp_push,
tiqr) and **force_token_non_static** (the same with ssh_key and
smartcard), assigned to nothing.

Both commands take a comma separated list and replace the one there;
**""** empties it, so it no longer limits anything. A type OTPme does
not know is refused. They ask first; **-f** does not.

> **force_token_types *policy* *types***  
> The token types let in, e.g. **totp,fido2**. Needs
> **edit:force_token_types**.
>
> **force_pass_types *policy* *types***  
> The pass types let in, e.g. **otp,smartcard**. Needs
> **edit:force_pass_types**.

## Auth On Action Policy

Asks the user to log in again before an action: the client gets a new
JWT for the token the user is logged in with. A site has
**auth_on_action**, on every object.

It does not ask in API mode (directly on a node, without the daemons),
over the local socket of a node, and not for the tokens and roles on its
whitelist.

A hook is an action on an object type, e.g. **user change_pin** or
**unit pre_add_user**. A new policy gets every hook there is. **show**
*policy* lists the ones it has (**HOOKS**) and the ones removed by hand
(**REMOVED_HOOKS**). Every object type has these; a command of another
name is in brackets:

> add, add_acl, add_attribute, add_extension, add_object_class,
> add_policy, change_auto_disable (auto_disable), change_description
> (description), change_info (info), change_unit (move), del_acl,
> del_attribute, del_object_class, delete (del), disable,
> disable_acl_inheritance, enable, enable_acl_inheritance, export,
> get_acls (list_acls), modify, remove_extension, remove_orphans,
> remove_policy, rename, show_config_parameters (show_config).

The hooks an object type has on top of these are in its man page,
section **AUTH ON ACTION HOOKS**.

The commands ask first; **-f** does not.

> **add_hook *policy* *object_type* *hook***  
> **remove_hook *policy* *object_type* *hook***  
> Ask, or no longer ask, before that action. A hook OTPme does not know
> for the object type is refused. A removed hook is remembered, so
> **update_hooks** does not bring it back; **add_hook** does, and
> forgets the removal. Needs **add:hook**, **remove:hook**.
>
> **update_hooks *policy***  
> Add the hooks registered after the policy was added, e.g. by an OTPme
> update, except the ones removed by hand. Needs **add:hook**.
>
> **reauth_timeout *policy* *time***  
> How long one login again holds while the user keeps working: every
> action within it starts it anew. Default 30s; 0 asks before every
> action. A number of seconds, or with a unit like **5m**. Needs
> **edit:reauth_timeout**.
>
> **reauth_expiry *policy* *time***  
> How long it holds at most, from the first login again, however busy
> the user is. Default 0, no limit. Has to be above **reauth_timeout**.
> Needs **edit:reauth_expiry**.
>
> **whitelist_token *policy* *user/token***  
> **unwhitelist_token *policy* *user/token***  
> **whitelist_role *policy* *role***  
> **unwhitelist_role *policy* *role***  
> Tokens and roles that are never asked. A token in a role counts,
> however deep the roles are nested. The role is looked for in this
> site. Needs **add:whitelist**, **remove:whitelist**.

## Default Units Policy

Says in which unit a new object goes when **add** names no unit. It is
assigned to users and works for what that user adds. Every new user gets
**default_units**, which names the usual unit of each type, e.g.
**users** for a user and **hosts** for a host.

When a user adds an object without a unit, it goes to the unit that the
policy of that user names for its type. If the policy names none, or the
unit is gone, it goes to the usual unit of the type. The same holds for
lines without a unit in **otpme-tool mass_object_add**. Hosts and nodes
that join, and templates, always go to the usual unit.

A user has one defaultunits policy. To give a user another one, remove
**default_units** first. **show** *policy* lists the units as
**DEFAULT_UNITS**.

Commands:

> **set_unit *policy* *object_type* \[*unit*\]**  
> Set the unit for *object_type*. *unit* is the path below the site,
> e.g. **it/users**. Without *unit*, the type has none again and goes to
> its usual unit. *object_type* is one of:
>
> accessgroup, ca, client, device, dictionary, group, host, node, pass,
> policy, pool, resolver, role, scope, script, share, user, vlan. Needs
> **add:default_unit** to set a type the first time,
> **edit:default_unit** to change it, **remove:default_unit** to clear
> it.

## Default Groups Policy

Gives new users a default group and puts them into more groups. It is
assigned to units and works for users added to that unit; a unit above
or the site does not count. A new site has **default_groups** on the
unit **users**, with no groups in it, and every unit added later gets it
too (from **default_policies**).

When a user is added without **--group** and without a template that
names a group, the user gets the default group of the policy. Without
one, it is the group named like the site, e.g. **berlin** on the site
**berlin** (**root** for the admin user).

When a user is added without **--groups** and gets a default token, that
token is added to each group of the policy; groups hold tokens, not
users. With **--no-default-token** nothing is added.

Who assigns the policy to a unit needs the same rights on its groups as
for setting them (see below). **show** *policy* lists them as
**DEFAULT_GROUP** and **DEFAULT_GROUPS**.

Commands:

> **add_group *policy* *group***  
> Add a group. Needs **add:default_group** on the policy and
> **add:token** on the group.
>
> **remove_group *policy* *group***  
> Remove a group. Needs **remove:default_group**.
>
> **default_group *policy* *group***  
> Set the default group. **""** as *group* removes it.
>
> Needs **edit:default_group** on the policy and
> **add:default_group_user** on the group.

## Default Roles Policy

Puts the default token of new users into roles. It is assigned to units
and works for users added to that unit; a unit above or the site does
not count. A new site has **default_roles** on the unit **users**, with
the role **REALM_USER** in it, and every unit added later gets it too
(from **default_policies**).

When a user is added and gets a default token, that token is added to
each role of the policy. **--roles** adds its roles on top. **--role**
turns the policy off for this user: the token goes to that role only,
also not to **REALM_USER**. With **--no-default-token** nothing is
added.

Who assigns the policy to a unit needs **add:token** on each of its
roles. **show** *policy* lists them as **DEFAULT_ROLES**.

Commands:

> **add_default_role *policy* *role***  
> Add a role. Needs **add:default_role** on the policy and **add:token**
> on the role.
>
> **remove_default_role *policy* *role***  
> Remove a role. Needs **remove:default_role**.

## Default Policies Policy

Says which policies a new object gets. It is assigned to sites and
units. A new object gets them from the unit it is added to, a unit right
below the site from the site, and a token from the unit of its user. A
unit further up does not count.

The policy lists policies per object type. A new object gets the ones
listed for its type, without a check of rights; if one cannot be
assigned, the object is not added. Entries for site and realm do
nothing: those get their policies when they are made.

A new site has **default_policies** on the site and on every unit, and
it lists itself for units, so every unit added later has it too. It
lists **auth_on_action** for every type; **password_strength** for host,
node, token and user; **default_units** and **token_acls** for user; and
**default_groups**, **default_roles**, **object_templates** and
**default_policies** for unit.

Who assigns the policy needs what assigning each of its policies needs.
**show** *policy* lists them as **DEFAULT_POLICIES**, e.g.
**user:\[auth_on_action,default_units\]**.

Commands:

> **add_default_policy *policy* *object_type* *policy_name***  
> Add *policy_name* for *object_type*. It must be a policy of this site
> that can be assigned to that type. Needs **add:default_policy**, and
> what assigning *policy_name* needs, e.g. **add:token** on each role of
> a defaultroles policy.
>
> **remove_default_policy *policy* *object_type* *policy_name***  
> Remove it. Needs **remove:default_policy**.

## ID Range Policy

Says which uidNumber and gidNumber a new user or group gets. A user or
group added without one gets the next free number from the policy of its
unit; if the unit has none, or none for that attribute, from the policy
of the site. A unit further up does not count. A number given by hand
must lie in a range too.

A new site has **id_range** with **uidNumber:s:70000-80000** and
**gidNumber:s:70000-80000**, or the ranges given with **--id-ranges**.
Ranges must not overlap with any range of any idrange policy, also of
other sites.

A range is written *\<attribute\>:\<type\>:\<start\>-\<end\>*, e.g.
**uidNumber:s:70000-80000**. *attribute* is **uidNumber** or
**gidNumber**. Type **s** hands out the numbers in order, going on after
the last one handed out; at the end of the range it starts over. Type
**r** takes a free number at random. Several ranges are separated by
commas.

**show** *policy* lists **ID_RANGES**, **VERIFY_NEW_ID** and
**RECHECK_ID_RANGES**.

Commands:

> **add_id_range *policy* *range,...***  
> Add ranges. If one of them is wrong or overlaps, none is added. Needs
> **add:idrange**.
>
> **del_id_range *policy* *range***  
> Remove a range. Needs **delete:idrange**.
>
> **enable_id_check** *policy*  
> **disable_id_check** *policy*  
> Before a number is handed out, check that no user or group has it. On
> by default. Without it, type **s** takes the number after the last one
> handed out unchecked. Needs **enable:id_check** or
> **disable:id_check**.
>
> **enable_id_range_recheck** *policy*  
> **disable_id_range_recheck** *policy*  
> When a range of type **s** has no free number after the last one
> handed out, look for gaps from its start. Off by default. Needs
> **enable:id_range_recheck** or **disable:id_range_recheck**.

## Token ACLs Policy

Gives a new token its ACLs. It is assigned to users; every new user gets
**token_acls**. When a token is added to the user, the policy adds:

> **user ACLs**  
> on the user, for the new token: what a token may do with its user.
>
> **token ACLs**  
> on the new token, for the token itself and for the default token of
> the user.
>
> **creator ACLs**  
> on the new token, for the token that added it, when that one belongs
> to another user (e.g. an admin).

A token type can bring more of its own. A token gets the ones its type
knows, the others are left out. When a token is deleted, the same ones
are taken away. When a token is moved to another user, the user and
token ACLs of the old user's policy are taken away and those of the new
user's policy are given, whatever ACL inheritance and **--keep-acls**
say; the creator ACLs stay. The user **TOKENSTORE** gets no user and
token ACLs. A change to the policy counts for tokens added or deleted
after it.

A new site has **token_acls** with the user ACLs **view_all**,
**gen_keys**, **encrypt**, **decrypt** and **sign**; the token ACLs
**view**, **edit:pin**, **edit:password** and **delete**; and the
creator ACLs **view**, **edit** and **delete**.

**show** *policy* lists them as **USER_ACLS**, **TOKEN_ACLS** and
**TOKEN_CREATOR_ACLS**.

Commands:

> **add_user_acl** *policy* *acl*  
> **del_user_acl** *policy* *acl*  
> Add or remove a user ACL. It must be an ACL of users. Needs
> **add:user_acl** or **del:user_acl**.
>
> **add_token_acl** *policy* *acl*  
> **del_token_acl** *policy* *acl*  
> Add or remove a token ACL. It must be an ACL of some token type. Needs
> **add:token_acl** or **del:token_acl**.
>
> **add_creator_acl** *policy* *acl*  
> **del_creator_acl** *policy* *acl*  
> Add or remove a creator ACL. It must be an ACL of some token type.
> Needs **add:creator_acl** or **del:creator_acl**.

## Object Templates Policy

Says which template a new user or host is made from. It is assigned to
units; every new unit gets **object_templates**. When a user or host is
added to the unit, it gets the template the policy has for its type.

From its template, a user or host gets the policies, extensions, object
classes and attributes, and whether ACL inheritance is on. A user also
gets the group of the template, if none is given; its key, agent, login
and auth script and whether they are enabled; and autosign. Templates
get no template, nor do admins and base or internal users. A template
given with **otpme-user add --template** or **otpme-host add
--template** wins over the policy. **otpme-user add --no-template** and
**otpme-host add --no-template** add one without any template.

A new user or host is made from the template of the policy without a
check of rights, and a new user gets the group of the template. So who
sets a template, or assigns the policy to a unit, needs **use** on the
template. **--template** needs **use** as well.

A new site has the templates **user_template** and **host_template** in
the unit **templates**, and **object_templates** with them.

**show** *policy* lists them as **OBJECT_TEMPLATES**.

Commands:

> **set_template** *policy* *object_type* {*template*\|**""**}  
> Set the template for **user** or **host**. It must be a template of
> the site, e.g. one added with **otpme-user add -t**. **""** removes
> it. Needs **set_template**, and **use** on the template.

# OPTIONS

**--type *TYPE***  

The policy type. Needed for **add** and for every command in **POLICY
TYPE DETAILS**, e.g. **otpme-policy --type idrange add_id_range id_range
uidNumber:s:80001-89999**. It can stand anywhere on the command line.

The options of each command are described with that command above.

Global options are available for all commands. See **otpme**(1) for
details.

# CONFIG PARAMETERS

A policy takes these. What each of them does, and how a parameter is
resolved, is in **otpme**(7). The settings of a policy type are no
config parameters, they are made with the commands of the type, see
**POLICY TYPE DETAILS**.

**changelog (bool, default: true)**  
Write the commands that change the policy into its changelog, see
**Object Changelog**.

**allow_changelog_clearing (bool, default: true)**  
Allow **clear_changelog** on the policy.

# EXAMPLES

## Password Policy

**otpme-policy --type password add strong_pw**  
A new password policy already asks for upper- and lowercase, a number, a
special character and a strength check.

**otpme-policy --type password password_min_len strong_pw 12**  
At least 12 characters.

**otpme-policy --type password pin_min_len strong_pw 6**  
PINs of at least 6 digits.

**otpme-policy --type password test --password "MyP@ss123" strong_pw**  
Try a password against it.

**otpme-user remove_policy alice password_strength**  
**otpme-user add_policy alice strong_pw**  
Give it to alice instead of the one of the site: a user has one password
policy.

## Login Time Restrictions

**otpme-policy --type logintimes add office**  
**otpme-policy --type logintimes login_times office "\* 8-17 \* \* 1-5"**  
Monday to Friday, 8:00 to 17:59.

**otpme-accessgroup add_policy vpn office**  
Logins through the access group vpn only then.

## Auto-Disable Temporary Access

**otpme-policy --type autodisable add temp_access**  
**otpme-policy --type autodisable auto_disable temp_access +90D**  
Disable after 90 days.

**otpme-policy --type autodisable auto_disable -u temp_access +30D**  
Or instead: disable after 30 days without use.

**otpme-user add_policy contractor1 temp_access**  
Give it to contractor1.

## Force Two-Factor Authentication

**otpme-policy --type forcetoken add require_2fa**  
**otpme-policy --type forcetoken force_token_types require_2fa totp,fido2**  
Only TOTP and FIDO2 tokens.

**otpme-accessgroup add_policy vpn require_2fa**  
Logins through the access group vpn only with those.

## Protect Sensitive Operations

**otpme-policy --type authonaction add protect_ops**  
A new one asks before every action there is.

**otpme-policy --type authonaction reauth_timeout protect_ops 5m**  
One login again holds 5 minutes of work.

**otpme-policy --type authonaction whitelist_role protect_ops SITE_ADMIN**  
Admins are never asked.

**otpme-user remove_policy alice auth_on_action**  
**otpme-user add_policy alice protect_ops**  
Give it to alice instead of the one of the site.

## Units for New Objects

**otpme-policy --type defaultunits add it_units**  
**otpme-policy --type defaultunits set_unit it_units user it/users**  
**otpme-policy --type defaultunits set_unit it_units host it/servers**  
Users and hosts go to these units.

**otpme-user remove_policy alice default_units**  
**otpme-user add_policy alice it_units**  
For what alice adds without naming a unit.

## ID Ranges

**otpme-policy --type idrange add it_ids**  
**otpme-policy --type idrange add_id_range it_ids uidNumber:s:10000-60000**  
User IDs from 10000 to 60000, in order.

**otpme-unit add_policy it it_ids**  
New users in the unit it get theirs from here.

# AUTH ON ACTION HOOKS

An auth on action policy can ask for a login again before these actions.
See **Auth On Action Policy** above. A policy has the hooks every object
type has, and these; a command of another name is in brackets:

> add_creator_acl, add_default_group, add_default_policy,
> add_default_role, add_hook, add_id_range, add_token_acl, add_user_acl,
> add_whitelist (whitelist_role or whitelist_token),
> change_default_group (default_group), change_force_pass_types
> (force_pass_types), change_force_token_types (force_token_types),
> change_login_times (login_times), change_password_min_len
> (password_min_len), change_pin_min_len (pin_min_len),
> change_reauth_expiry (reauth_expiry), change_reauth_timeout
> (reauth_timeout), change_strength_checker (strength_checker),
> change_strength_checker_opts (strength_checker_opts), del_creator_acl,
> del_id_range, del_token_acl, del_user_acl, disable_require_lower,
> disable_require_number, disable_require_special,
> disable_require_upper, disable_strength_checker, enable_require_lower,
> enable_require_number, enable_require_special, enable_require_upper,
> enable_strength_checker, remove_default_group, remove_default_policy,
> remove_default_role, remove_hook, remove_whitelist (unwhitelist_role
> or unwhitelist_token), set_config_parameter (config), set_default_unit
> (set_unit), set_template, update_hooks.

# FILES

*/var/lib/otpme/tree/*  
The objects of the realm, on the nodes and, by sync, on the hosts. A
policy is the directory *\<policy\>.policy* in the directory of its
unit, e.g.
*\<realm\>.realm/\<site\>.site/policies.unit/password_strength.policy/*,
with its settings in *object.json*. Change them with the commands above,
not in the file.

# SEE ALSO

**otpme**(1), **otpme**(7), **otpme-site**(1), **otpme-unit**(1),
**otpme-user**(1), **otpme-token**(1), **otpme-group**(1),
**otpme-role**(1), **otpme-accessgroup**(1), **otpme-host**(1),
**otpme-node**(1), **otpme-client**(1), **otpme-dictionary**(1),
**otpme-trash**(1), **otpme-tool**(1), **cron**(5)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2026 the2nd. License: GPLv3
