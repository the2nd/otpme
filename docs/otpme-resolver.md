# NAME

otpme-resolver - fetch users, groups and units from LDAP servers into
OTPme

# SYNOPSIS

**otpme-resolver** \[**--type ldap**\] *command* \[*options*\]
\[*resolver*\]

# DESCRIPTION

**otpme-resolver** adds and sets up resolvers. A resolver fetches users
and groups from LDAP servers, e.g. OpenLDAP, and with
**enable_sync_units** also their units, and brings OTPme in line with
them. LDAP is the only type. A new resolver starts disabled. Once
enabled, the master node of the site runs it every **sync_interval**;
**run** runs it by hand. Only with **enable_deletions** does a run
delete objects.

A resolver is trusted: it adds its objects without ACL checks, with the
**uidNumber** and **gidNumber** the server hands out, and with
**enable_sync_units** into the unit their DN names. So only an admin may
add, change, run or delete a resolver. Looking at one can be given to
others by ACLs.

# COMMANDS

## Resolver Management

Only an admin may add, change, run or delete a resolver, whatever ACLs
somebody holds; see **DESCRIPTION**. On this page such a command says
**(admin only)** after its ACL. The ACLs of the commands that only read
can be given to others.

**--type ldap add **\[**--template** *template*\] *resolver*  
Add a resolver of that type; **ldap** is the only one.  
It starts disabled, so it does not run before it is set up, see
**enable**. **--template openldap** fills in the LDAP filters, key
attributes and attribute mappings of an OpenLDAP server for users,
groups and units; it is the only template.  
With a path, e.g. **ldap/corp**, it goes into that unit; else into the
unit a **defaultunits** policy names, or into **resolvers**.  
Needs the ACL **add:resolver** on the unit (admin only).

**del** \[**--no-trash**\] *resolver*  
Delete the resolver. It goes to the trash, see **otpme-trash**(1);
**--no-trash** deletes it right away.  
If the resolver has added objects, it says how many of each type and
asks whether to delete them as well, then asks to type its name. With
the global option **-f** it asks nothing and deletes the resolver only,
not its objects. A running resolver is refused.  
Needs the ACL **delete:object** (admin only).

**show** \[**-a**\] \[**-z** *N*\] \[**--fields** *F1,F2*\] \[**--limit** *N*\] \[**--policy-limit** *N*\] \[**--sort-by** *field*\] \[**--reverse**\] \[**--raw**\] \[**--csv**\] \[**--csv-sep** *sep*\] \[*resolver*\]  
Without a resolver: a table of them, with their unit, type, status,
whether they delete objects (**sync_deletions**), policies, ACL
inheritance and description.

**-a**  
Also the resolvers you may only look at, not just the ones you may
change.

**-z *N***  
How many resolvers to print.

**--fields *F1,F2***  
Print these columns and no others, in the order they are named.

**--limit *N*, **--policy-limit** *N***  
How many policies to print per resolver.

**--sort-by *field*, **--reverse****  
Which column to sort by, and the other way round.

**--raw, **--csv**, **--csv-sep** *sep***  
**--raw** leaves the header and the borders out, **--csv** prints one
row per line with **;** between the columns, and **--csv-sep** uses
another separator.

A column you may not see says **-**. With a resolver named, this prints
the object itself instead of a table row, one value per line.

**show_oid** \[**--full**\] *resolver*  
Show the OID of the resolver: **resolver\|\<realm\>/\<site\>/\<name\>**.
With **--full** the full OID, which names the unit as well:
**resolver\|\<realm\>/\<site\>/\<unit_path\>/\<name\>**.  
Needs the ACL **view_public:object**.

**show_uuid *resolver***  
Show the UUID of the resolver.  
Needs the ACL **view_public:object**.

**list** \[**-a**\] \[**--attribute** *attribute*\] \[*pattern*\]  
The names of the resolvers, one per line; with *pattern* only those it
matches, see **SELECTING OBJECTS** in **otpme**(1). **-a** also lists
the ones you may only look at. **--attribute** matches the pattern
against that attribute instead of the name.

**enable *resolver***  
Enable the resolver. The master node of the site then runs it by itself,
every **sync_interval**, see **Sync Configuration**.  
Needs the ACL **enable:object** (admin only).

**disable *resolver***  
Disable the resolver: it no longer runs by itself. **run** still runs it
by hand.  
Needs the ACL **disable:object** (admin only).

**touch *resolver***  
Write the resolver anew, as it is, e.g. after an upgrade of its object
version.  
Needs the ACL **touch** (admin only).

**auto_disable** \[**-u**\] *resolver* *time*  
Set auto-disable time. It is either a relative time with a leading
**+**, e.g. **+30D**, or an absolute one, e.g. **"09:53 13.06.2023"**.
The units are **s**, **m**, **h**, **D**, **W**, **M** and **Y**, see
**otpme**(7). A relative time counts from when it is set, and again from
when the resolver is enabled. **0** removes it. It is refused for an
object the realm or a site comes with, e.g. the admin user; a time set
on one before does nothing. Use **-u** to disable the resolver once it
was unused for the given time. That takes a relative time; a resolver
that was never used counts from when this was set. A resolver is used
when it runs.  
Needs the ACL **edit:auto_disable** (admin only).

**rename *resolver* *new_name***  
Rename the resolver. A running resolver is refused.  
Needs the ACL **rename** (admin only).

**move** \[**--keep-acls**\] *resolver* *unit*  
Move the resolver to another unit. Whether its ACLs change with it, see
**enable_acl_inheritance**; **--keep-acls** leaves them as they are.  
Needs the ACL **move** (admin only).

## Resolver Operations

An LDAP resolver handles the object types **unit**, **group** and
**user**. **--object-types** takes some of them, separated by commas,
e.g. **user,group**; another type is refused. Without it a command works
on all three.

**run** \[**--object-types** *types*\] *resolver*  
Fetch the objects from the servers and bring OTPme in line with them:
add the new ones, change the changed ones. Only with
**enable_deletions** does it also delete the objects it added that the
servers no longer have. They go to the trash, see
**add_resolver_objects_to_trash** under **CONFIG PARAMETERS**. It asks
first; the global option **-f** skips the question.  
This is what the master node does by itself for an enabled resolver. A
run counts as a use of the resolver, see **auto_disable -u**. A resolver
that is already running is refused.  
Needs the ACL **run** (admin only).

**test** \[**--object-types** *types*\] *resolver*  
Change nothing, but show what a run would do. Before that it connects to
every server and checks that they all return the same number of objects;
this check takes all types. At the end it says whether there were
errors.  
Needs the ACL **test** or **run** (admin only).

**get_objects** \[**--object-types** *types*\] *resolver*  
The objects this resolver has added to OTPme, not those on the servers:
their names per type, printed as a Python dict.  
Needs the ACL **get_objects**.

**delete_objects** \[**--object-types** *types*\] *resolver*  
Delete the objects this resolver has added: users first, then groups,
then units. They go to the trash, see **add_resolver_objects_to_trash**
under **CONFIG PARAMETERS**. No ACL is checked on the objects
themselves. It says how many of each type there are and asks to type the
name of the resolver; the global option **-f** skips the question. With
no objects it says so and asks nothing.  
An object that cannot be deleted does not stop the others; the command
then says how many were left. A running resolver is refused.  
Needs the ACL **delete:objects** (admin only).

## Sync Configuration

How and when a resolver runs. Each command asks first; the global option
**-f** skips the question.

**sync_interval *resolver* *interval***  
How long the master node waits after a run before it runs the enabled
resolver again, e.g. **300**, **5m** or **1h** (see **otpme**(7) for the
units). The default is 300 seconds.  
The master node looks every 30 seconds, so a shorter interval does not
run it more often. 0 or less is refused.  
Needs the ACL **edit:sync_interval** (admin only). To see it, **show**
needs the ACL **view:sync_interval**.

**key_attribute *resolver* *object_type* *attribute***  
The attribute by which the resolver finds an object of that type again
on the next run, e.g. **entryUUID**. It must not change on the server,
so a name is a bad choice. *object_type* is **unit**, **group** or
**user**; **--template openldap** sets **entryUUID** for all three.  
A run refuses a type that has an LDAP filter but no key attribute,
before it connects. A server entry without the attribute, or with more
than one value of it, stops the whole run. That is on purpose: with
**enable_deletions**, an entry left out would delete its object.  
Needs the ACL **edit:key_attribute** (admin only). To see it, **show**
needs the ACL **view:key_attribute**.

**enable_sync_units *resolver***  
Also fetch the organizational units, add them as units, and put each
object into the unit its DN names.  
Needs the ACL **enable:sync_units** (admin only).

**disable_sync_units *resolver***  
Do not fetch units; users and groups go into the default unit of their
type. This is the default.  
Needs the ACL **disable:sync_units** (admin only).

**enable_deletions *resolver***  
Let a run also delete the objects this resolver has added and the
servers no longer return.  
Needs the ACL **enable:deletions** (admin only). To see whether it is
on, **show** needs the ACL **view:deletions**; the table has it in the
column **sync_deletions**.

**disable_deletions *resolver***  
A run no longer deletes objects. This is the default.  
Needs the ACL **disable:deletions** (admin only).

## LDAP Configuration

Where an LDAP resolver connects, how it logs in, and what it fetches.
These commands need **--type ldap**; without it they are unknown and
only the help is printed. Each command asks first; the global option
**-f** skips the question.

A run needs at least one server, and for each type with a filter a key
attribute (see **key_attribute**) and a mapping for **name**. Without
them it stops before it connects and says what is missing. A type
without a filter is not fetched.

**--type ldap add_server *resolver* *server_uri***  
Add a server, as **ldaps://*host***\[**:*port***\] or
**ldap://*host***\[**:*port***\]. **ldaps://** speaks TLS from the
start, by default on port 636. **ldap://** always starts TLS first
(StartTLS), by default on port 389; a server that cannot do that is
refused when the resolver runs. The resolver never logs in without
encryption. Anything else is refused.  
A run uses the first server it can reach. **test** asks all of them and
checks that they agree.  
Needs the ACL **add:ldap_server** (admin only). To see them, **show**
needs the ACL **view:ldap_server**.

**--type ldap del_server *resolver* *server_uri***  
Remove a server, written as it was added.  
Needs the ACL **del:ldap_server** (admin only).

**--type ldap ca_data *resolver* \[*ca_cert_file*\]**  
The CA certificates, as a PEM file, that the certificate of the server
must be issued by. The file is read on your side and stored in the
resolver, so every node that runs it has them. Without a file, or with
an empty one, they are removed.  
Without them the certificate of the server is not checked at all, and
every connection warns about it: somebody in between could read the
login and hand the resolver objects of their own.  
Needs the ACL **edit:ca_data** (admin only).

**--type ldap ldap_base *resolver* *base_dn***  
Where the filters search, e.g. **dc=example,dc=org**.  
Needs the ACL **edit:ldap_base** (admin only). To see it, **show** needs
the ACL **view:ldap_base**.

**--type ldap login_dn *resolver* *dn***  
The DN the resolver logs in as, e.g.
**cn=otpme,ou=services,dc=example,dc=org**; **""** removes it.  
Needs the ACL **edit:login_dn** (admin only). To see it, **show** needs
the ACL **view:login_dn**.

**--type ldap login_password *resolver* \[*password*\]**  
The password for that DN. Without one, it asks for it without showing
it; an empty one removes it.  
The resolver logs in only with both a DN and a password; with only one
of them it searches anonymously.  
Needs the ACL **edit:login_password** (admin only). The password is a
secret: to see it, **show** needs the ACL **view:login_password**, given
as such (or **view_all**); plain **view** is not enough.

**--type ldap add_ldap_filter *resolver* *object_type* *filter***  
Search for objects of that type (**unit**, **group** or **user**) with
an LDAP filter, e.g. **(objectclass=posixGroup)**. A type can have
several filters; each one is searched, and the results are put together.
Units are only fetched with **enable_sync_units**.  
Needs the ACL **add:ldap_filter** (admin only). To see them, **show**
needs the ACL **view:ldap_filter**.

**--type ldap del_ldap_filter *resolver* *object_type* *filter***  
Remove a filter, written as it was added.  
Needs the ACL **del:ldap_filter** (admin only).

**--type ldap add_ldap_attribute *resolver* *object_type* *src_attr* \[*dst_attr*\]**  
Take the LDAP attribute *src_attr* of the server as *dst_attr* of the
OTPme object; without *dst_attr* under the same name. A second mapping
to the same *dst_attr* replaces the first.

These *dst_attr* mean something of their own: **name**, the name of the
object (needed); **uuid**, its UUID; **uidNumber**, **gidNumber** and
**loginShell**, its POSIX values. Every other one becomes an LDAP
attribute of the object, e.g. **mail**.

A new user gets the group with the same **gidNumber** as its primary
group, if that group came with the same run; else it gets the default
group.

Needs the ACL **add:attribute_mapping** (admin only). To see them,
**show** needs the ACL **view:attribute_mapping**; it prints them as
***dst_attr*:*src_attr***.

**--type ldap del_ldap_attribute *resolver* *object_type* *src_attr***  
Remove the mapping of that server attribute. An unknown one is refused
before the question.  
Needs the ACL **del:attribute_mapping** (admin only).

## Policy Management

A *policy* is the name of a policy, not a path. It is looked for in the
site of the resolver. Which policies there are, and what each of them
does, is in **otpme-policy**(1).

Two policy types fit a resolver:

-   **authonaction** asks for a login again before the actions of the
    resolver, see **AUTH ON ACTION HOOKS**.

-   **autodisable** disables the resolver after a while; a disabled
    resolver no longer runs by itself. One set with **auto_disable -u**
    (unused for) counts from its last run.

Attaching and detaching ask before they change anything; the global
option **-f** skips the question.

**add_policy *resolver* *policy***  
Attach a policy to the resolver.  
A policy has a list of object types it is for; one that does not name
**resolver** is refused. So is a second policy of a type that allows
only one per object, even when the first one is disabled, and a policy
the resolver already has.  
Needs the ACL **assign:policy** (admin only).

**remove_policy *resolver* *policy***  
Remove a policy from the resolver.  
Needs the ACL **remove:policy**, and that one verbatim: a plain
**remove** does not cover it (admin only).

**list_policies** \[**--return-type** *TYPE*\] \[**--policy-types** *t1,t2*\] *resolver*  
List the policies attached to the resolver, the disabled ones too,
marked **(disabled)**. Use **--return-type** to select the attribute
returned (**name**, **read_oid**, **full_oid**, **uuid**); without it
the names. Only the names are marked. Use **--policy-types** to list
only policies of the given types; these are policy types, not policy
names.  
Needs the ACL **view:policies**.

## ACL Management

An ACL says what somebody may do with this resolver. The somebody is a
role or a token, never a user. On a resolver only the ACLs that read can
be given to others: **view_public:object**, **view** and the **view:**
ACLs, **get_objects**. The ACLs of everything that changes it are admin
only, whatever ACLs somebody holds; see **DESCRIPTION**.

What the three forms **acl**, **+acl** and **++acl** mean is under
**ACLs** in **otpme**(7). Tab completion after **add_acl** offers the
ACLs a resolver knows. A resolver has no default ACLs, **+acl** and
**++acl**: nothing lies in a resolver that could get them.

Adding and removing ask first; the global option **-f** skips the
question.

**add_acl *resolver* *owner_type* *owner* *acl*\[:*value*\]\[,*acl*\[:*value*\]\]**  
Give a role or a token one or more ACLs on this resolver.  
*owner_type* is **role** or **token**. *owner* names it the way
**list_acls** prints it: a role as *site/name*, or by its name alone on
its own site; a token as *user/token*. An ACL can carry a value, for
example **view:sync_interval**. To give several ACLs at once, separate
them with commas: **view:sync_interval,get_objects**.  
Needs the ACL **add:acl** (admin only).

**del_acl *resolver* *acl*\[,*acl*\]**  
Take those ACLs away again.  
Here an *acl* is the whole entry, owner and all, the way **list_acls**
prints it: **role:berlin/helpdesk:get_objects**.  
Needs the ACL **delete:acl** (admin only).

**list_acls *resolver***  
Show the ACLs that lie on this resolver, i.e. who may do what with it.  
Needs the ACL **view:acl**.

**enable_acl_inheritance *resolver***  
Let a move of the resolver swap its default ACLs: what the old unit
handed down is taken away, and what the new unit hands down is given. It
does not by default; a move then leaves the ACLs of the resolver as they
are.

Only a move asks this. A new resolver gets the default ACLs of its unit,
and **add_acl -a** or **-r** on a unit reach it either way. A move with
**--keep-acls** leaves its ACLs alone all the same.

Needs the ACL **enable:acl_inheritance** (admin only).

**disable_acl_inheritance *resolver***  
A move leaves the ACLs of the resolver as they are again.  
Needs the ACL **disable:acl_inheritance** (admin only).

## Configuration and Attributes

A resolver has three config parameters, see **CONFIG PARAMETERS**.

**config** \[**-d**\] \[**-a**\] *resolver* *parameter* \[*value*\]  
Set a parameter on the resolver.

**-d**  
Remove the parameter from the resolver, or with a value only that one
value from a list. It is not set back to a default: what applies
afterwards is what the units or the site say.

**-a**  
Append the value to a parameter that holds a list, instead of replacing
what is there.

Needs the ACL **set:config:\<parameter\>** (admin only).

**show_config *resolver* \[*parameter*\]**  
The parameters set on the resolver itself, or only the one named.
Nothing is shown for a parameter that the resolver gets from a unit or
from the site.  
Needs the ACL **view:config:\<parameter\>**.

**get_config *resolver* *parameter***  
What the parameter comes to for the resolver, once the resolver, its
units and the site have been looked at. So this answers what applies,
where **show_config** answers what was set here.  
Needs the ACL **view:config:\<parameter\>**.

**description *resolver* \[*description*\]**  
Set the description. Without one OTPme asks and offers the current text
for editing.  
Needs the ACL **edit:description** (admin only).

**info** \[**--language** *LANG*\] *resolver* \[*info*\]  
Set free-form info text. If *info* is omitted, the current info text is
opened in the editor named by the **EDITOR** environment variable.  
Without **--language** the text is the administrator's own note. Nothing
shows the info of a resolver to a user, so a text for a language stays a
note as well.  
Needs the ACL **edit:info** (admin only).

**dump_info** \[**--language** *LANG*\] *resolver*  
Write one of those texts to stdout. **--language** picks which one;
without it you get the note of the administrator.  
Needs the ACL **view:info**.

**show_info** *resolver*  
List the languages the resolver has a text for, one per line, with the
first line of the text. The note of the administrator comes first, as
**-**. An empty text is not listed.  
Needs the ACL **view:info**.

## Object Changelog

Every change to the object writes an entry: who made it, when, and what
was done. The first entry is the one of **add**. A change can carry a
comment of its own, through the global option **--changelog**.

**run** and **delete_objects** write an entry too when you run them by
hand. The runs the master node makes by itself every **sync_interval**
do not, or the changelog would grow by an entry every few minutes.

Nothing is written where the **changelog** config parameter is off. It
is read along the cascade (resolver, unit, site). Without any value
anywhere it is on.

An *entry_id* is the number the listing shows in front of an entry,
counted from 0.

Only the comment of an entry can be changed or removed. What was done
and by whom stays as it is.

A command that changes something asks first; the global option **-f**
skips the question.

**changelog *resolver***  
Show the changelog of the resolver, one entry per line: its *entry_id*,
the time, who made the change and what was done, then a detail in round
brackets and the comment in square brackets where there are any. Needs
the ACL **view:changelog**.

**edit_changelog *resolver* *entry_id* *comment***  
Set the comment of that entry, or replace the one it has. That writes an
entry of its own. Needs the ACL **edit:changelog** (admin only).

**del_changelog *resolver* *entry_id***  
Remove the comment of that entry. The entry itself stays, and an entry
without a comment is refused. That writes an entry of its own. Needs the
ACL **edit:changelog** (admin only).

**clear_changelog *resolver***  
Remove every entry of the changelog. Afterwards it holds one entry: that
it was cleared.  
This needs more than the ACL **clear:changelog** (admin only): the
config parameter **allow_changelog_clearing** has to allow it (see
**otpme**(7)). It is true by default, but where no value is found at
all, clearing is refused. A value set on the token you are signed in
with counts first. Without one, the value of the object counts, read
along its cascade.

## Export and Cleanup

**export** \[**--password** *password*\] *resolver*  
Write the whole object of the resolver to stdout, as JSON: its type,
servers, mappings, ACLs, policies, config parameters and the rest.
**otpme-tool import** reads it back.  
The only secret of a resolver is the login password of an LDAP resolver.
Without **--password** it is in the output in a form anyone can read.
With **--password** it is encrypted with a key derived from that
password, and import needs the same password.  
Needs the ACL **export** (admin only).

**remove_orphans *resolver***  
Remove references to objects that are gone: orphan ACLs and policies of
the resolver.  
It asks once for what it found; the global option **-f** skips the
question.  
Needs the ACL **remove:orphans** (admin only).

# OPTIONS

**--type *type***  
The resolver type; **ldap** is the only one. Needed for **add** and for
every command in **LDAP Configuration**: without it they are unknown,
and only the help is printed. It may stand anywhere on the line; this
page puts it in front.

Every other option belongs to one command and is described with that
command above.

Global options work with every command, see **otpme**(1).

# CONFIG PARAMETERS

Set them with **config**, see **Configuration and Attributes**. A value
is looked up on the resolver, then on its unit and the units above it,
then on the site; the first one found counts. A parameter the site names
in **force_site_config_parameters** is taken from the site, whatever the
resolver or its units say. The full descriptions are in **otpme**(7).

**add_resolver_objects_to_trash (bool, default: true)**  
Whether the objects the resolver deletes go to the trash, where
**otpme-trash**(1) can restore them; see **run** and **delete_objects**.
False deletes them right away.

**changelog (bool, default: true)**  
Whether the commands that change the resolver write an entry into its
changelog, see **Object Changelog**.

**allow_changelog_clearing (bool, default: true)**  
Whether **clear_changelog** is allowed on the resolver. A value on the
token you are signed in with counts first, see **Object Changelog**.

Set on the site or a unit, not on the resolver:

**max_resolver_name_len (int, default: 64)**  
The longest name a resolver may get, checked by **add** and **rename**.

The objects a resolver adds are checked like any other: a user or a
group with a name longer than **max_user_name_len** or
**max_group_name_len** is not added, and the run reports it.

# EXAMPLES

## Setting Up an OpenLDAP Resolver

**otpme-resolver --type ldap add --template openldap ldap1**  
Add the resolver with the filters, key attributes and mappings of an
OpenLDAP server.

**otpme-resolver --type ldap add_server ldap1 ldaps://ldap.example.org**  
Add the server.

**otpme-resolver --type ldap ca_data ldap1 /etc/ssl/certs/example-ca.pem**  
Check the certificate of the server against this CA.

**otpme-resolver --type ldap ldap_base ldap1 dc=example,dc=org**  
Search below this DN.

**otpme-resolver --type ldap login_dn ldap1 cn=otpme,ou=services,dc=example,dc=org**  
Log in as this DN.

**otpme-resolver --type ldap login_password ldap1**  
Asks for the password of that DN.

## Without a Template

**otpme-resolver --type ldap add_ldap_filter corp group '(objectclass=posixGroup)'**  
Fetch groups with this filter. The quotes keep the shell off the
brackets.

**otpme-resolver key_attribute corp group entryUUID**  
Find a group again by its entryUUID.

**otpme-resolver --type ldap add_ldap_attribute corp group cn name**  
Take cn as the name of the group; a run needs a mapping for name.

## Running the Resolver

**otpme-resolver test ldap1**  
Show what a run would do, without changing anything.

**otpme-resolver run ldap1**  
Add and change the objects.

**otpme-resolver run --object-types user ldap1**  
Only the users.

**otpme-resolver sync_interval ldap1 1h**  
Run it every hour once it is enabled.

**otpme-resolver enable ldap1**  
Let the master node run it by itself.

# AUTH ON ACTION HOOKS

An auth on action policy can ask for a login again before these actions.
See **Auth On Action Policy** in **otpme-policy**(1). A resolver has the
hooks every object type has, and these; a command of another name is in
brackets:

> add_attribute_mapping (add_ldap_attribute), add_filter
> (add_ldap_filter), add_server, change_ca_data (ca_data),
> change_key_attribute (key_attribute), change_ldap_base (ldap_base),
> change_login_dn (login_dn), change_login_password (login_password),
> del_attribute_mapping (del_ldap_attribute), del_filter
> (del_ldap_filter), del_server, delete_objects, disable_deletions,
> disable_sync_units, enable_deletions, enable_sync_units,
> get_resolver_objects (get_objects), run, set_config_parameter
> (config), set_sync_interval (sync_interval), test.

Most commands that change the resolver run **modify** first, then their
own hook. **del** and **config** run only their own. So a policy on
**modify** asks before most changes, but not before **del**, **config**,
**run**, **test** or **get_objects**.

The runs the master node does by itself never ask: they have no token to
ask for. A policy on **run** only asks before **otpme-resolver run** by
hand.

# FILES

*/var/lib/otpme/tree/*  
The objects of the realm. A resolver is the directory
*\<name\>.resolver* in the directory of its unit, e.g.
*\<realm\>.realm/\<site\>.site/resolvers.unit/ldap1.resolver/*, with its
settings in *object.json*, the login password encrypted. It is synced to
the nodes only, not to the hosts. Change it with the commands above, not
in the file.

# SEE ALSO

**otpme**(1), **otpme**(7), **otpme-unit**(1), **otpme-user**(1),
**otpme-group**(1), **otpme-policy**(1), **otpme-trash**(1),
**otpme-tool**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
