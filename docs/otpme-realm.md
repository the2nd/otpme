# NAME

otpme-realm - set up a realm and manage the object at the top of it

# SYNOPSIS

**otpme-realm** *command* \[*options*\] \[*realm*\]

# DESCRIPTION

A realm is the whole of an OTPme installation: its sites, and in them
the units, users, tokens, hosts and all the rest. Its name is usually a
DNS domain, e.g. **example.org**, and it is the top entry of the LDAP
tree, **dc=example,dc=org**.

The realm object is what this command works on. It holds the CA data of
the realm, which site is its master site, its ACLs, its auth on action
policy and its LDAP attributes. It holds no key, no secret and no config
parameter.

**init** creates the realm with its CA and its master site, on the first
machine. Further sites are added on the master site with **otpme-site
add**, see **otpme-site**(1).

**The realm is changed on its master site.** Every site has a copy of
it, and the sync brings the one of the master site. On another site only
its own description of the realm can be set, and **touch** and the
switches for authentication and sync run there.

There is one realm for now. Adding another realm, to trust it and its
users, is not implemented yet.

For the bigger picture — realms, sites, how a login runs across them —
see **otpme**(7).

# COMMANDS

## Realm Initialization

**init \[*options*\] *realm* *site* *fqdn* \[*address*\]**  
Create a new realm on the machine you run it on. This is the first
command of a new OTPme installation.  
It creates the realm and its first site, the one named by *site*, which
is the master site of the realm. With them come the CA of the realm, the
CA of the site, the certificate of the site, and the node of this
machine, which is the master node. The node is named after the host name
of the machine. Then init adds the base objects of the site and the
admin user **root** with its token. The realm gets its auth on action
policy, see **Policy Management** below.  
The names of the realm and the site are stored in lower case.  
*fqdn* becomes the auth, the management and the SSO FQDN of the site, as
with **otpme-site add**, see **otpme-site**(1).  
*address* is the floating address of the site. Without it the address is
looked up in DNS under *fqdn*; a name with more than one address is
refused, and so is one with none. Unless it is 127.0.0.1, init puts the
address on an interface once to test it, and takes it off again: the
interface **FLOATING_IP_IFACE** names in **otpme.conf**(5), else the one
whose network holds the address. An address that is already on an
interface is refused.  
If **KEY_COMMAND** in **otpme.conf**(5) names a file and there is no key
in it yet, init makes the master key and asks for its password, or reads
it with the global option **--stdin-pass**.  
A machine that already has a realm is refused.  
init runs on the machine itself, not through a daemon, and needs no ACL:
there is nobody yet who could hold one.  
The options are under **INIT OPTIONS**.

## Display

**show \[**-a**\] \[**-z** *N*\] \[**--fields** *F1,F2*\] \[**--limit** *N*\] \[**--policy-limit** *N*\] \[**--sort-by** *field*\] \[**--reverse**\] \[**--raw**\] \[**--csv**\] \[**--csv-sep** *sep*\] \[*realm*\]**  
Without a realm: a table of the realms, with their type, whether
authentication and synchronization with them are on, their policies and
their description.  
The type is **Local** for your own realm and **Remote** for any other.
Another realm cannot be added yet, that is not implemented: the table
has your own realm alone.

**-a**  
Also the realms you may only look at, not just the ones you may change.

**-z *N***  
How many realms to print.

**--fields *F1,F2***  
Print these columns and no others, in the order they are named. The
names are the ones in the header of the table. A name with a **+** in
front is added to the columns that are shown anyway, and one with a
**-** is left out of them.

**--limit *N*, **--policy-limit** *N***  
How many policies to print per realm.

**--sort-by *field*, **--reverse****  
Which column to sort by, and the other way round.

**--raw, **--csv**, **--csv-sep** *sep***  
For reading with something other than your eyes: **--raw** leaves the
header and the borders out, **--csv** prints one row per line with **;**
between the columns, and **--csv-sep** uses another separator.

A column you may not see says **-**. Auth opens with **view:auth**,
**enable:auth** or **disable:auth**, Sync the same with **sync**,
Policies with **view:policies**, **assign:policy** or **remove:policy**,
Description with **view:description** or **edit:description**.  
With a realm named, this prints the object itself instead of a table
row: one value per line, and with them what the table leaves out — the
UUID of the master site (**view:master**), the path of the realm CA
(**view:ca**) and its certificates and CRLs in base64
(**view:ca_data**). A value you may not see is left empty, or says **-**
for **AUTH_ENABLED** and **SYNC_ENABLED**.  
That needs the ACL **view_public:object**, also for a token in the admin
role: here the admin role does not count. Only the admin token of the
site, the one of **root**, needs none. init gives it to the site admin
role and to the realm user role of the first site, and **otpme-site
add** to those of the new site.

<!-- -->

**show_oid \[**--full**\] *realm***  
Show the OID of the realm: **realm\|\<realm\>**. **--full** is accepted
and shows the same.  
Needs the ACL **view_public:object**.

**show_uuid *realm***  
Show the UUID of the realm.  
Needs the ACL **view_public:object**.

<!-- -->

**list \[**-a**\] \[**--attribute** *attribute*\] \[*pattern*\]**  
List the realm names, and with a pattern only those that match it, see
**SELECTING OBJECTS** in **otpme**(1). You get the realms you may
change; **-a** adds those you may only look at.  
**--attribute** matches the pattern against that attribute instead of
the name.

## Authentication and Synchronization

These four are for a realm other than your own: whether its users may
log in here, and whether objects are synchronized with it. Another realm
cannot be added yet, that is not implemented, so for now they do
nothing: with your own realm authentication and synchronization are
always on. Enabling says so, and disabling is refused.

Each asks first; the global option **-f** skips the question. Each
writes an entry to the changelog.

**enable_auth *realm***  
Let the users of the realm log in again.  
Needs the ACL **enable:auth**.

**disable_auth *realm***  
Refuse logins of the users of the realm. Admins, and users with
**enable_disabled_login** (see **otpme-user**(1)), still get in.  
Needs the ACL **disable:auth**.

**enable_sync *realm***  
Synchronize with the realm again.  
Needs the ACL **enable:sync**.

**disable_sync *realm***  
Stop synchronizing with the realm. Nothing reads this setting of a realm
yet.  
Needs the ACL **disable:sync**.

## CA Data

The CA data of the realm is the chain OTPme trusts: the certificate and
the CRL of the realm CA, and those of the CA of every site. It is kept
in the realm, and every node and host writes it to
*/etc/otpme/ssl/ca.pem* (**SSL_CA_FILE** in **otpme.conf**(5)).  
It is brought up to date by itself: when a site gets its CA, and when a
CA revokes a certificate or gets a new CRL.

Both need their ACL even for a token in the admin role: here the admin
role does not count. Only the admin token of the site, the one of
**root**, needs none.

**dump_ca_data *realm***  
Write the CA data to stdout, the certificates and CRLs one after the
other in PEM.  
Needs the ACL **view:ca_data**.

**update_ca_data *realm***  
Build the CA data again from the CAs and write it to the realm and to
the CA file of this machine. If it changed, the daemons are reloaded.  
On a site other than the master site of the realm this changes the copy
there, and the next sync brings the one of the master site.  
Asks first; the global option **-f** skips the question.  
Needs the ACL **update_ca_data**.

## Policy Management

A realm takes one policy and no other: the auth-on-action policy that
realm init attaches.

A policy object lives in a site, a realm does not. A realm that carried
a policy would carry the one of whichever site answered first, and the
admins of that site would then decide what the whole realm enforces.

The policies of the realm run for its own hooks, and for the sites,
which are its children: when a site is added (**pre_add_site**,
**post_add_site**). Any other policy type would act on every site added
to the realm. Auth on action is the exception: somebody has to be asked
before these run. See **AUTH ON ACTION HOOKS** below.

Below the sites the realm is never asked: a unit, a user or a token
reads the policies of itself and of its parent, never those of the
realm.

Attaching and detaching ask before they change anything; the global
option **-f** skips the question.

**add_policy *realm* *policy***  
Attach the auth-on-action policy to the realm. Any other policy is
refused, and so is a second one of this type.  
*policy* is the name of a policy, not a path.  
Needs the ACL **assign:policy**.

**remove_policy *realm* *policy***  
Remove a policy from the realm.  
Needs the ACL **remove:policy**, and that one verbatim: a plain
**remove** does not cover it. Detaching a policy takes away what it
enforces, so it must not be cheaper than attaching one.

**list_policies \[**--return-type** *TYPE*\] \[**--policy-types** *t1,t2*\] *realm***  
List the policies attached to the realm, the disabled ones too, marked
**(disabled)**. Use **--return-type** to select the attribute returned
(**name**, **read_oid**, **full_oid**, **uuid**). Use **--policy-types**
to list only policies of the given types; these are policy types, not
policy names.  
Needs the ACL **view:policies**.

## ACL Management

An ACL says what somebody may do with the realm. The somebody is a role
or a token, never a user, and it can be of any site.

For the realm a token in the admin role is not an admin: it needs the
ACL like anybody else. Only the admin token of the site, the one of
root, needs none.

ACLs are set on the master site, as all changes to the realm are;
another site refuses **add_acl** and **del_acl**. The sync takes them to
the other sites.

A realm only has normal ACLs, for the realm object alone. It hands
nothing down: a site does not inherit from the realm. So a default ACL,
**+acl** or **++acl**, is refused, and there is no **-r** and no **-a**.
Tab completion after **add_acl** offers the ACLs a realm knows.

Adding and removing ask first, once for the whole command; the global
option **-f** skips the question.

**add_acl *realm* *owner_type* *owner* *acl*\[:*value*\]\[,*acl*\[:*value*\]\]**  
Give a role or a token one or more ACLs on the realm.  
*owner_type* is **role** or **token**. *owner* names it the way
**list_acls** prints it: a role as *site/name*, e.g.
**munich/helpdesk**, or by its name alone on its own site; a token as
*user/token*, e.g. **alice/login**. An ACL can carry a value, for
example **view:auth**. To give several ACLs at once, separate them with
commas: **view:auth,view:sync**.  
Needs the ACL **add:acl**.

**del_acl *realm* *acl*\[,*acl*\]**  
Take those ACLs away again.  
Here an *acl* is the whole entry, owner and all, the way **list_acls**
prints it: **role:munich/helpdesk:view:auth**.  
Needs the ACL **delete:acl**.

**list_acls *realm***  
Show the ACLs that lie on the realm, i.e. who may do what with it. This
works on every site.  
Needs the ACL **view:acl**.

## Extensions and LDAP Attributes

The realm is also an LDAP entry, the top one: for the realm
**example.org** it is **dc=example,dc=org**. An extension is what gives
it one: the object classes it is of, and the attributes those classes
allow. What **ldapd** serves and what **show_ldif** prints comes from
them.

A realm has the extension **base**. It makes the realm a **dcObject**,
with **dc**, the first part of the realm name. **dc** names the entry,
so it cannot be changed or removed, and neither can **base**.

The other class **base** knows for a realm is **organization**. A new
realm does not have it. It needs a name, **o**, and setting one adds the
class: **add_attribute example.org o=Example**. After that the realm can
take what **organization** allows, an address or a phone number for
example.

These are changes to the realm, so they are made on the master site;
another site refuses them. They ask first; the global option **-f**
skips the question.

**add_extension *realm* *extension***  
Add an extension to the realm. No other extension is for realms, so for
a realm this is refused today.  
Needs the ACL **add:extension**.

**remove_extension *realm* *extension***  
Take it away again, with the classes and attributes it brought. An
extension that brings the attribute naming the entry cannot be removed,
and for a realm that is **base**.  
Needs the ACL **remove:extension**.

**add_attribute *realm* *attribute***=**\[*value*\]**  
Set an LDAP attribute of the realm.

Only an attribute one of its classes allows. One that only
**organization** allows gives the realm that class; set **o** first, the
class needs it. An attribute can hold more than one value, so this adds
one and leaves the others.

The ACL is per attribute, **add:attribute:***attribute*, and a plain
**add:attribute** covers all of them.

**modify_attribute *realm* *attribute* *old_value* *new_value***  
Put *new_value* in the place of *old_value*, and leave the other values
of the attribute alone.  
The ACL is **edit:attribute:***attribute*.

**del_attribute *realm* *attribute***=**\[*value*\]**  
Remove that value, or the whole attribute where no value is given.  
A mandatory attribute of a class the realm is of cannot be removed,
**o** while it has **organization** for example, and neither can **dc**.
The ACL is **delete:attribute:***attribute*.

**add_object_class *realm* *class***  
Add an LDAP object class. For a realm that can only be **organization**.
This adds the class without **o**, which it needs; **add_attribute**
with **o** adds both.  
Needs the ACL **add:object_class**.

**del_object_class *realm* *class***  
Remove an object class again, with the attributes only it allows: for
**organization** that is **o** and what was set with it. It says which
ones before it asks, and changes nothing before the answer. **dcObject**
stays, it allows **dc**.  
Needs the ACL **delete:object_class**.

**show_ldif *realm* \[**-a** *attribute1,attribute2*\]**  
The realm as LDAP sees it. **-a** prints only those attributes.  
It shows the attributes in **ldif_whitelist_attributes**, see
**otpme**(7), and the ones you have **view:attribute:***attribute* for;
the others are left out. By default that leaves **dn**, **objectClass**
and **entryUUID** of a realm.

## Configuration and Attributes

**description *realm* \[*description*\]**  
Set the description. Without one OTPme asks and offers the current text
for editing. Each site keeps its own description of the realm: it can be
set on any site, and the sync does not change it.  
Needs the ACL **edit:description**.

**info \[**--language** *LANG*\] *realm* \[*info*\]**  
Set free-form info text. If *info* is omitted, the current text is
opened in the editor named by the **EDITOR** environment variable, or in
vim; that reads the text first and needs **view:info** as well. Without
**--language** the text is the administrator's own note. Nothing shows
the info of a realm to a user, so a text for a language stays a note as
well. The info is set on the master site and comes to the other sites
with the sync; another site refuses it.  
Needs the ACL **edit:info**.

**dump_info \[**--language** *LANG*\] *realm***  
Write one of those texts to stdout. **--language** picks which one;
without it you get the note of the administrator.  
Needs the ACL **view:info**.

**touch *realm***  
Write the index entries, the ACLs and the LDAP entry of the realm again,
on this site. Any site can do that.  
Needs the ACL **touch**.

description, info and touch ask first; the global option **-f** skips
the question. description and info write an entry to the changelog.

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

The changelog of the realm is kept on the master site and comes to the
other sites with the sync. There **edit_changelog**, **del_changelog**
and **clear_changelog** are refused. A change another site may make,
such as **description** or **enable_auth**, writes its entry on that
site only; the next sync of the realm from the master site takes it
away.

A realm holds no config parameters, so the parameter **changelog**
cannot switch its changelog off.

**changelog *realm***  
Show the changelog of the realm, one entry per line: its *entry_id*, the
time, who made the change and what was done, then a detail in round
brackets and the comment in square brackets where there are any.  
Needs the ACL **view:changelog**.

**edit_changelog *realm* *entry_id* *comment***  
Set the comment of that entry, or replace the one it has. That writes an
entry of its own.  
Needs the ACL **edit:changelog**.

**del_changelog *realm* *entry_id***  
Remove the comment of that entry. The entry itself stays, and an entry
without a comment is refused. That writes an entry of its own.  
Needs the ACL **edit:changelog**.

**clear_changelog *realm***  
Remove every entry of the changelog. Afterwards it holds one entry: that
it was cleared.  
This needs more than the ACL **clear:changelog**: the config parameter
**allow_changelog_clearing** has to allow it (see **otpme**(7)). It is
true by default, but where no value is found at all, clearing is
refused. For a realm only the value set on the token you are signed in
with counts: the realm itself has none. So clearing needs that token to
have **allow_changelog_clearing** set to true, see **otpme-token**(1).

## Export and Cleanup

**export \[**--password** *password*\] *realm***  
Write the whole object of the realm to stdout, as JSON: its ACLs,
policies, LDAP attributes, the certificates and CRLs of the CA and the
rest, but not the sites in it. **otpme-tool import** reads it back.  
A realm holds no key and no secret, so **--password** has nothing to
encrypt: the output is in clear either way.  
Needs the ACL **export**.

**remove_orphans *realm***  
Remove references to objects that are gone: ACLs of a role or token that
was deleted, or of an ACL group that was deleted, and policies that were
deleted.  
It asks once for what it found; the global option **-f** skips the
question. It is a change to the realm, so it is made on the master site;
another site refuses it.  
Needs the ACL **remove:orphans**.

# INIT OPTIONS

These options are used with the **init** command.

## CA Certificate Options

init makes two CAs: the CA of the realm, which signs itself, and the CA
of the master site, which the CA of the realm signs.

**--ca-valid *DAYS***  
How many days the certificates of both CAs are valid. The default is the
config variable **default_ca_validity**, 5475 days.

**--ca-key-len *BITS***  
The length of the keys of both CAs. The default is
**default_ca_key_len**, 4096 bits.

**--country *COUNTRY***  
Set CA certificate country field.

**--state *STATE***  
Set CA certificate state field.

**--locality *LOCALITY***  
Set CA certificate locality field.

**--organization *ORG***  
Set CA certificate organization field.

**--ou *OU***  
Set CA certificate organizational unit field.

**--email *EMAIL***  
Set CA certificate email field.

The six fields go into both CAs, and from the CA of the site into the
certificate of the site and the one of the master node. None of them is
needed.

## Site and Node Certificate Options

**--site-valid *DAYS***  
How many days the certificate of the site is valid. The default is
**default_site_validity**, 5475 days.

**--site-key-len *BITS***  
The length of the key of the site certificate. The default is
**default_site_key_len**, 3072 bits. Note that **otpme-tool join** uses
**--site-key-len** for the key of the CA, see **otpme-tool**(1).

**--node-valid *DAYS***  
How many days the certificate of the master node is valid. The default
is **default_node_validity**, 5475 days.

**--node-key-len *BITS***  
The length of the key of the master node certificate. The default is
**default_node_key_len**, 4096 bits.

## Dictionary and ID Range Options

**--dicts *dict1,dict2***  
The word dictionaries the master site checks the strength of a password
against, as with **otpme-site add**: only the ones OTPme comes with, put
into the **password_strength** policy in this order. Without this option
the site gets none. See **otpme-site**(1) for the names, and
**otpme-dictionary**(1) to add more later.

**--id-ranges *range1,range2***  
The ranges the master site takes the numbers of new users and groups
from, each written as *attribute***:***type***:***first***-***last*.
They go into its ID range policy, see **otpme-policy**(1).  
Without this option the site gets **uidNumber:s:70000-80000** and
**gidNumber:s:70000-80000**.

**--no-index-indices**  
Do not create the indices of the index database at the end of init. Use
it only for special setups, like very small test realms.

# OPTIONS

Every option belongs to one command and is described with that command
above; those of **init** are under **INIT OPTIONS**.

Global options work with every command, see **otpme**(1).

# EXAMPLES

## A new realm

On the first machine, as root:

**otpme-realm init example.org berlin login.berlin.example.org 10.0.0.10**  
Create the realm **example.org** with its master site **berlin**.
**login.berlin.example.org** is the name the clients reach the site
under, and 10.0.0.10 its floating address. This machine becomes the
master node.

**otpme-realm init --organization Example --country DE example.org berlin login.berlin.example.org**  
The same, with two fields for the certificates of the CAs. The address
is looked up in DNS under the name.

## The name of the organization in LDAP

On the master site:

**otpme-realm add_attribute example.org o=Example**  
The realm becomes an **organization** as well: **dc=example,dc=org**
gets **o: Example**.

## Letting a role of another site see the realm

On the master site:

**otpme-realm add_acl example.org role munich/helpdesk view**  
The role **helpdesk** of the site **munich** may see the whole realm
object, not only its public part.

## The CA chain of the realm

**otpme-realm dump_ca_data example.org \> ca.pem**  
The certificates and CRLs every node and host has in
**/etc/otpme/ssl/ca.pem**.

# AUTH ON ACTION HOOKS

An auth on action policy can ask for a login again before these actions.
See **Auth On Action Policy** in **otpme-policy**(1). A realm has the
hooks every object type has, and these:

> disable_auth, disable_sync, enable_auth, enable_sync,
> set_config_parameter, update_ca_data.

It also has **pre_add\_\<type\>** before an object of that type is added
below the realm, and **post_add\_\<type\>** after it, e.g.
**pre_add_site**. *\<type\>* is one of:

> site.

# FILES

*/var/lib/otpme/tree/*  
The objects of the realm, on the nodes and, by sync, on the hosts. The
realm is the directory *\<realm\>.realm*, e.g. *example.org.realm/*,
with its settings in *object.json*; the directories of its sites are in
it. Change them with the commands above, not in the file.

*/etc/otpme/ssl/ca.pem*  
The CA data of the realm, as every node and host writes it, see
**dump_ca_data**. **SSL_CA_FILE** in **otpme.conf**(5) names another
place.

# SEE ALSO

**otpme**(1), **otpme**(7), **otpme.conf**(5), **otpme-site**(1),
**otpme-node**(1), **otpme-ca**(1), **otpme-policy**(1),
**otpme-dictionary**(1), **otpme-user**(1), **otpme-token**(1),
**otpme-tool**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2026 the2nd. License: GPLv3
