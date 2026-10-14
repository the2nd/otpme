# NAME

otpme-scope - say what an application may learn about a user

# SYNOPSIS

**otpme-scope** *command* \[*options*\] \[*scope*\]

# DESCRIPTION

A scope is what an application asks for when it sends a user to the SSO
portal to sign in, and what OTPme hands out in return. **email** gets
the application the mail address of the user, **profile** their name,
**groups** the groups they are in. The names come from OpenID Connect;
OTPme is the OpenID Provider and the application is the Relying Party,
see **otpme**(7).

The application is a **client** of the realm, and that is the word for
the object as well — the one **otpme-client**(1) manages. Where this
page says application, that object is what holds it.

A scope object says who may hand that scope out. It holds tokens and
roles — the users that may give it away — and the clients that may
receive it. A scope is granted only if all three agree: the application
asked for it, the token of the user has it, and the client has it. See
**HOW A SCOPE IS GRANTED**.

So this is the second of two questions about one login. The access group
of the client decides whether the user gets in at all (see
**otpme-accessgroup**(1)); the scopes decide what the application is
told about them afterwards.

A scope lives in the **scopes** unit of a site, and the nodes of that
site are what answers with it. OIDC does not cross a site boundary: a
scope is only ever looked up on the site that owns it, and the clients
and groups it takes are the ones of that site.

Every site is created with seven scopes of its own, see **THE SCOPES A
SITE BRINGS**.

# COMMANDS

## Scope Management

**add *scope* \[*scope_id*\]**  
Create a scope.  
It is created in the **scopes** unit of your site; a path puts it into
another unit, and **move** takes it there afterwards. A name is unique
in its site, whatever unit it sits in.  
*scope_id* is the name the application sends, and without one it is the
name of the scope, see **THE SCOPE ID**.  
A new scope holds nobody. Both sides have to be named: the clients that
receive it, with **add_client**, and the roles whose users hand it out,
with **add_role**.  
Needs the ACL **add:scope** on the unit it is created in, not on the
scope — there is none yet.

**del \[**--no-trash**\] *scope***  
Delete a scope. It goes to the trash, from where **otpme-trash**(1) can
bring it back; **--no-trash** deletes it right away.  
Needs the ACL **delete:object** on the scope, or **delete:scope** on the
unit it sits in.  
A scope a site brings with it cannot be deleted. Switch it off with
**disable** instead.

**show \[**-a**\] \[**-z** *N*\] \[**--fields** *F1,F2*\] \[**--limit** *N*\] \[**--policy-limit** *N*\] \[**--sort-by** *field*\] \[**--reverse**\] \[**--raw**\] \[**--csv**\] \[**--csv-sep** *sep*\] \[*scope*\]**  
Without a scope: a table of all of them, with their unit, their roles,
tokens, clients and groups, their scope ID and their policies.

**-a**  
Also the scopes you may only look at, not just the ones you may change.

**-z *N***  
How many scopes to print.

**--fields *F1,F2***  
Print these columns and no others. The names are the ones in the header
of the table.

**--limit *N*, **--policy-limit** *N***  
How many items to print per scope, and the same for the policies alone.

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
With a scope named, this prints the object itself instead of a table
row: its scope ID and its roles, tokens, clients and groups, each line a
value. A reference to an object that is gone is printed as the bare
UUID, which is how **remove_orphans** has something to find.

**list \[**-a**\] \[*regex*\]**  
List the scope names, and with a regex only those that match it. You get
the scopes you may change; **-a** adds those you may only look at.

**enable *scope***  
Enable a disabled scope.  
Needs the ACL **enable:object**.

**disable *scope***  
Switch a scope off without deleting it.  
It is then handed out to nobody, and it is gone from the
*scopes_supported* list of the discovery document. An application that
asks for it still gets its login; the scope is simply missing from the
answer.  
This is what to do with a scope a site brings with it, which cannot be
deleted.  
Needs the ACL **disable:object**.

**rename *scope* *new_name***  
Rename a scope.  
The name is not what the application sends — that is the scope ID, and a
rename leaves it alone. A scope a site brings with it cannot be
renamed.  
Needs the ACL **rename:object**.

**move \[**--keep-acls**\] *scope* *unit***  
Move the scope into another unit. Its ACLs move with it: the default
ACLs of the old unit are taken away and those of the new one are
applied. **--keep-acls** leaves the ACLs of the scope as they are.  
A scope does not inherit ACLs by default, see **enable_acl_inheritance**
below.

**scope_id *scope* *scope_id***  
Set the name the application sends for this scope, see **THE SCOPE
ID**.  
Needs the ACL **edit:scope_id**.

**touch *scope***  
Re-index the object to fix potential index problems.  
Needs the ACL **touch**.

## Who May Hand the Scope Out

A token is named by its path, *user***/***token*. A role is named by its
name, which is looked for in the site of the scope, or as
*site***/***role* to take one from another site of the realm.

**add_token *scope* *token_path***  
Let this token hand the scope out.  
Whoever signs in with it can give the scope to an application that asks
for it — if that application has the scope as well.  
Needs the ACL **add:token**.

**remove_token *scope* *token_path***  
Take the token out of the scope. A UUID is taken as well, which is how a
reference to a token that is gone is cleared out.  
Needs the ACL **remove:token**.

**list_tokens \[**--return-type** *TYPE*\] \[**--token-types** *t1,t2*\] \[*scope*\]**  
List the tokens in the scope, disabled ones included.  
**--return-type** selects what is printed per token; the default is the
path. **--token-types** lists only tokens of the given types, for
example **hotp,totp**.  
Needs the ACL **view:tokens**.

**add_role *scope* *role***  
Let every token of this role hand the scope out.  
This is the way to do it for more than one user: a role holds the
tokens, the scope holds the role. A role from another site is named
*site***/***role*.  
Needs the ACL **add:role**.

**remove_role *scope* *role***  
Take the role out of the scope.  
Needs the ACL **remove:role**.

**list_roles *scope***  
List the roles in the scope.  
Needs the ACL **view:roles**.

## Which Applications Get It

A client is named by its name and has to be a client of the site of the
scope, see **otpme-client**(1).

**add_client *scope* *client***  
Let this application receive the scope.  
One scope ID per application: adding a client that another scope with
the same scope ID already holds is refused, and the other scope is
named. That is what keeps the answer unambiguous, see **THE SCOPE
ID**.  
Needs the ACL **add:client**.

**remove_client *scope* *client***  
Take the application out of the scope. From then on it no longer gets
it, whatever it asks for.  
Needs the ACL **remove:client**.

**list_clients *scope***  
List the applications in the scope, disabled ones included.  
Needs the ACL **view:clients**.

## The Groups Claim

This list is read by one scope only, the one whose scope ID is
**groups**. What it does is under **THE GROUPS CLAIM** below.

**add_group *scope* *group***  
Allow this group to be named to the application.  
The group has to be a group of the site of the scope, see
**otpme-group**(1).  
Needs the ACL **add:group**.

**remove_group *scope* *group***  
Take the group off the list. The application is no longer told about it,
even if the user is in it.  
Needs the ACL **remove:group**.

**list_groups *scope***  
List the groups on the list.  
Needs the ACL **view:groups**.

## Object Changelog

Every change to the object writes an entry: who made it, when, and what
was done. A change can carry a comment of its own, through the global
option **--changelog**.

An *entry_id* is the number the listing shows in front of an entry,
counted from 0.

Only the comment of an entry can be changed or removed. What was done
and by whom stays as it is.

**changelog *scope***  
Show the changelog of the scope. Needs the ACL **view:changelog**.

**edit_changelog *scope* *entry_id* *comment***  
Set the comment of that entry, or replace the one it has. Needs the ACL
**edit:changelog**.

**del_changelog *scope* *entry_id***  
Remove the comment of that entry. The entry itself stays, and an entry
without a comment is refused. Needs the ACL **edit:changelog**.

**clear_changelog *scope***  
Remove every entry of the changelog.  
This needs more than the ACL **clear:changelog**: the config parameter
**allow_changelog_clearing** has to allow it (see **otpme**(7)). It is
true by default, but where no value is found at all, clearing is
refused. OTPme asks the token you are signed in with first, then the
object.

## Policy Management

A *policy* is the name of a policy, not a path. It is looked for in the
site of the scope. Which policies there are, and what each of them does,
is in **otpme-policy**(1).

**add_policy *scope* *policy***  
Attach a policy to the scope.  
A policy has a list of object types it is for; one that does not name
**scope** is refused. So is a second policy of a type that allows only
one per object.  
Needs the ACL **assign:policy**.

**remove_policy *scope* *policy***  
Remove a policy from the scope.  
Needs the ACL **remove:policy**, and that one verbatim: a plain
**remove** does not cover it. Detaching a policy takes away what it
enforces, so it must not be cheaper than attaching one.

**list_policies \[**--return-type** *TYPE*\] \[**--policy-types** *t1,t2*\] *scope***  
List the policies attached to the scope. Use **--return-type** to select
the attribute returned (**name**, **read_oid**, **full_oid**, **uuid**).
Use **--policy-types** to list only policies of the given types; these
are policy types, not policy names.  
Needs the ACL **view:policies**.

## ACL Management

An ACL says what somebody may do with this scope. The somebody is a role
or a token, never a user.

What the three forms **acl**, **+acl** and **++acl** mean, and which
ACLs exist, is under **ACLs** in **otpme**(7).

**add_acl *scope* *owner_type* *owner* *acl*\[:*value*\]\[,*acl*\[:*value*\]\]**  
Give a role or a token one or more ACLs on this scope.  
*owner_type* is **role** or **token**, and *owner* the path of that role
or token. An ACL may carry a value, for example **view:clients**, and
several are separated by commas.  
Needs the ACL **add:acl**.

**del_acl *scope* *acl*\[,*acl*\]**  
Take those ACLs away again.  
Here an *acl* is the whole entry, owner and all, the way **list_acls**
prints it: **role:berlin/sso-admins:view**.  
Needs the ACL **delete:acl**.

**list_acls *scope***  
Show the ACLs that lie on this scope, i.e. who may do what with it.
Needs the ACL **view:acl**.

**enable_acl_inheritance *scope***  
Let the scope inherit the default ACLs of the unit above it.

A scope does not, and that is on purpose: whoever may change a unit full
of other objects should not get a say over who may hand out a scope by
that alone.

Only default ACLs are inherited. An ordinary ACL on the unit never is.

Moving the scope into another unit then takes away the default ACLs of
the old unit and applies those of the new one. While inheritance is off,
a move leaves the ACLs of the scope as they are.

Needs the ACL **enable:acl_inheritance**.

**disable_acl_inheritance *scope***  
Stop inheriting them. Only the ACLs on the scope itself count from then
on. Needs the ACL **disable:acl_inheritance**.

## Configuration

A config parameter is looked for on the scope, then on the units above
it, then on the site. The first value found is the one that applies, and
the realm holds none. A site can turn that around for a parameter it
names in **force_site_config_parameters,** and then its own value wins
(see **otpme**(7)).

Which parameters a scope takes is in **CONFIG PARAMETERS** below.

**config \[**-d**\] \[**-a**\] *scope* *parameter* \[*value*\]**  
Set a parameter on the scope.

**-d**  
Remove the parameter from the scope, or with a value only that one value
from a list. It is not set back to a default: what applies afterwards is
whatever the unit or the site says.

**-a**  
Append the value to a parameter that holds a list, instead of replacing
what is there.

Without a *value* the parameter is set to its default, which is not the
same as leaving it unset: the value then stands on the scope and nothing
above it is read any more.  
The ACL is per parameter, **set:config:***parameter*.

**show_config *scope* \[*parameter*\]**  
The config parameters set on the scope itself, or only the one named.  
Nothing is shown for a parameter that the scope gets from a unit or from
the site, and nothing for one whose ACL **view:config:***parameter* you
do not hold. The scope ID and the members of the scope are not config
parameters: **show** and **export** are where those are.

**get_config *scope* *parameter***  
What the parameter comes to for this scope, once the scope, its units
and its site have been looked at. So this answers what applies, where
**show_config** answers what was set here.  
Needs the ACL **view:config:***parameter*, the same one that opens it in
**show_config**.

**description *scope* \[*description*\]**  
Set the description. Without one OTPme asks and offers the current text
for editing.  
Needs the ACL **edit:description**.

**info \[**--language** *LANG*\] *scope* \[*info*\]**  
Set free-form info text. If *info* is omitted, the current text is
opened in the editor named by the **EDITOR** environment variable.  
Without **--language** the text is the administrator's own note about
the object, which no user is ever shown. With a language it is text for
the users in that language.  
Needs the ACL **edit:info**.

**dump_info \[**--language** *LANG*\] *scope***  
Print the info text, of that language or the administrator's own.  
Needs the ACL **view:info**.

## Export and Cleanup

**export \[**--password** *password*\] *scope***  
Write the whole object of the scope to stdout, as JSON.  
Without **--password** it is written as it is, in clear. With one, a key
is derived from that password and the object is encrypted with it; the
salt goes into the output, so the password is all you need to read it
back.  
What a scope holds are references by UUID — its tokens, its roles, its
clients, its groups — so an export says something only in the realm it
came from.  
Needs the ACL **export**.

**remove_orphans *scope***  
Remove references to objects that are gone.  
A token, a role or a client that is deleted leaves its UUID behind in
every scope that held it. Nothing is handed out to it any more — the
UUID resolves to nothing — but it stays in the object and **show**
prints it as a bare UUID. This clears those out, together with orphan
ACLs, policies and signatures.  
It asks once for everything it found; the global option **-f** skips the
question.  
A group that is gone is not cleaned up here: the group list is not one
of the lists this command walks, and **remove_group** wants a name. Such
a reference stays, and it does no harm — a group that does not resolve
is left out of the claim.  
Needs the ACL **remove:orphans**.

# HOW A SCOPE IS GRANTED

A login through the SSO portal grants a scope only if it is in all three
of these:

> -   what the application asked for, the *scope* parameter of its
>     */authorize* request,
>
> -   what the token of the user may hand out: the scopes that hold the
>     token, plus the scopes that hold one of its roles,
>
> -   what the application may receive: the scopes that hold that
>     client, roles not counted.

A disabled scope is in none of them.

Everything else is left out silently, in the order the application
asked. So an application that asks for **openid profile email** and
whose users have only **openid** and **profile** gets those two, and no
error. What it did get is in the answer of the token endpoint, as the
*scope* field. That is the shape of the mistake to look for: a user
signs in, the application is happy, and it knows nothing about them
because their token reaches no scope.

Nothing fills the user side by itself. A role is put into a scope with
**add_role** and stays there until it is taken out; the only ones that
come with somebody in them are the three default scopes of a site, which
hold its **SSO_USER** role.

A request that does not ask for **openid** at all is a different matter:
that one is refused with *invalid_scope*, because OpenID Connect says
every request has to carry it.

The claims of the granted scopes are handed out at */userinfo*. They are
in the ID Token as well only where the client, its unit or its site sets
**oidc_id_token_user_claims** (see **otpme**(7)).

What the user sees of all this is the consent screen of the portal,
which lists the scopes of the request with the values they would hand
over.

# THE SCOPE ID

The name of a scope is for the administrator, the scope ID is what goes
over the wire.

A scope ID may be used by more than one scope object, and that is the
point: every application that wants the **groups** scope needs its own
list of groups, so every one of them gets its own scope object with the
scope ID **groups**. A client can be in one scope per scope ID —
**add_client** refuses the second — so which object answers for which
application is never in doubt.

**add** takes the scope ID as its second argument, and without one it is
the name of the scope. **scope_id** changes it afterwards.

The discovery document of the site lists the scope IDs of all its
enabled scopes under *scopes_supported*, each one once. Which
application really gets which of them is still decided per scope object.

# THE GROUPS CLAIM

The **groups** scope tells an application which groups the user is in,
which is how applications like Nextcloud or Grafana decide what somebody
may do inside them. It is not a scope of the OIDC standard, but a widely
used one.

What the application is told is the overlap of two lists: the groups of
the user, and the groups on the scope. A group the user is in and the
scope does not name is not mentioned, and neither is one the scope names
and the user is not in.

So the scope is the list of groups an application is allowed to know
about. An application for one department does not learn the group
structure of the whole realm, and a group is never named to an
application that was not meant to see it.

The list is empty to begin with, which means no group is ever named.
Adding the scope to an application is not enough; the groups have to be
added as well.

The scope OTPme asks for this is the one whose **scope ID** is
**groups** and that holds this client.

# THE SCOPES A SITE BRINGS

Every site is created with seven scopes. They cannot be renamed or
deleted, only disabled.

Three of them — **openid**, **profile** and **email** — are also written
into the site parameter **oidc_default_scopes,** which is the list a new
OIDC client is given (see **otpme**(7)). Those three are given the
**SSO_USER** role as well, so whoever may use the portal can hand them
out, and an application created with the default scopes works without
anybody being added to a scope.

The other four hold nobody. A scope one of them is wanted from needs
both sides named: the client with **add_client**, and the users with
**add_role**.

**openid**  
Carries no claim of its own. Every request has to ask for it, and an
application that has it not granted sees it missing from the answer.

**profile**  
The name and the like: *name*, *given_name*, *family_name*,
*preferred_username*, and where the user has them *middle_name*,
*nickname*, *website*, *locale*, *updated_at* and *picture*.  
They are read from the LDAP attributes of the user — **cn**,
**givenName**, **sn**, **initials**, **displayName**, **labeledURI** —
and *locale* only where the user set a language of their own. *picture*
is a URL of the portal, and only where the user has a photo.

**email**  
The *email* claim, from the LDAP attribute **mail**, or from whatever
the site names in **oidc_email_attribute.**

**address**  
The *address* claim, built from **postalAddress** or **street**, **l**,
**st**, **postalCode** and **c**.

**phone**  
The *phone_number* claim, from the LDAP attribute **telephoneNumber**.

**offline_access**  
In OpenID Connect this is how an application says that it wants to go on
working for the user while they are not there: it asks for a refresh
token, with which it fetches new access tokens without the user signing
in again.  
It carries no claim, and OTPme reads it nowhere. Whether an application
gets a refresh token is decided by its grant types alone —
**refresh_token** has to be one of them, see **add_oidc_grant_type** in
**otpme-client**(1) — and nothing asks whether this scope was granted.  
So what it does today is appear in the *scope* field of the token
answer, and on the consent screen, where the portal has a line for it
(that screen is shown where **oidc_require_consent** is set, see
**otpme**(7)). Granting it to an application that has no
**refresh_token** grant type promises something it will not get; keeping
it from one that has the grant type takes nothing away.

**groups**  
The *groups* claim, see **THE GROUPS CLAIM**.

# OPTIONS

Every option belongs to one command and is described with that command
above.

Global options work with every command, see **otpme**(1).

# CONFIG PARAMETERS

A scope takes these:

**changelog (bool)**  
Whether the commands on this scope are written to its changelog.  
Default: true

**allow_changelog_clearing (bool)**  
Whether the changelog of this scope may be cleared, see
**clear_changelog** above.  
Default: true

What each of them does, and how a parameter is resolved, is in
**otpme**(7).

The parameters of the OIDC provider itself — **oidc_default_scopes**,
**oidc_email_attribute**, **oidc_id_token_user_claims** and the rest —
are set on the site, the unit or the client, not here.

# EXAMPLES

## Looking at what is there

**otpme-scope show**  
All scopes of the site with their members and their scope IDs.

**otpme-scope show profile**  
The **profile** scope itself: who may hand it out and which applications
get it.

**otpme-scope list_clients email**  
The applications that are told the mail address.

## A new application

**otpme-client add --enable-oidc wiki**  
Create the application. It is given the default scopes of the site,
which are **openid**, **profile** and **email**. Those three hold the
**SSO_USER** role already, so nothing has to be added here for them.

**otpme-accessgroup add_role wiki wiki-users**  
Let those users sign in to it. Who gets in is the access group of the
client — here one of the same name — and not the scope (see
**otpme-accessgroup**(1)).

**otpme-scope add_client phone wiki**  
Let the application have the phone number as well.

**otpme-scope add_role phone wiki-users**  
And let its users hand that one out. Both lines are needed: the client
side says which application may receive the scope, the role side who may
give it away.

## Group memberships for one application

**otpme-scope add wiki_groups groups**  
A scope of its own for the **wiki**, with the scope ID **groups**.

**otpme-scope add_client wiki_groups wiki**  
This one answers for the **wiki**.

**otpme-scope add_group wiki_groups wiki-editors**  

**otpme-scope add_group wiki_groups wiki-admins**  
The two groups the **wiki** may know about. Every other group of the
realm stays unmentioned.

**otpme-scope add_role wiki_groups wiki-users**  
The users that hand the scope out.

## Keeping something to yourself

**otpme-scope remove_client email mailinglist**  
The application no longer gets the mail address, whatever it asks for.

**otpme-scope disable address**  
Nobody hands out postal addresses on this site any more, and the scope
is gone from the discovery document.

## Handing the work over

**otpme-scope add_acl wiki_groups role it-support add:group,remove:group,view:groups**  
The service desk may change the group list of this one scope, and
nothing else about it.

**otpme-scope remove_orphans profile**  
Clear out the applications and tokens that were deleted since.

# SEE ALSO

**otpme**(1), **otpme**(7), **otpme-acls**(7), **otpme-client**(1),
**otpme-accessgroup**(1), **otpme-group**(1), **otpme-role**(1),
**otpme-token**(1), **otpme-user**(1), **otpme-site**(1),
**otpme-unit**(1), **otpme-policy**(1), **otpme-trash**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2026 the2nd. License: GPLv3
