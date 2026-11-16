# NAME

otpme-ca - the certificate authorities of a realm and its sites:
certificates, client certificates and CRLs

# SYNOPSIS

**otpme-ca** *command* \[*options*\] \[*ca*\]

# DESCRIPTION

**otpme-ca** shows the certificate authorities (CAs) of the realm, makes
client certificates with them, revokes those, and looks after the CRLs.

There are two kinds of CA, and no other:

> -   **REALM_CA**, made with the realm, in the master site. Its
>     certificate is signed by itself. It signs the CAs of the sites
>     that are not below another site.
>
> -   **SITE_CA**, made with each site. The CA of a site below another
>     site is signed by the CA of that one, the others by **REALM_CA**.
>     A **SITE_CA** signs the certificates of its site: of its hosts and
>     nodes when they join, of the site itself, and the client
>     certificates of **create_client_cert**.

No command adds or deletes a CA, see **CA Management**.

The certificates and CRLs of all CAs are the CA data of the realm. Every
host and node has it, and checks the certificate of the other side
against it, see **FILES**. Each CA keeps a CRL of what it has revoked,
see **CRL Management**.

# COMMANDS

## CA Management

There are only the CAs a realm and its sites come with: **REALM_CA** in
the master site, and **SITE_CA** in every site, both in the unit
**cas**. They are made with the realm and the site, and no command adds,
deletes, disables or renames one.

**show** \[**-a**\] \[**-z** *N*\] \[**--fields** *F1,F2*\] \[**--limit** *N*\] \[**--policy-limit** *N*\] \[**--sort-by** *field*\] \[**--reverse**\] \[**--raw**\] \[**--csv**\] \[**--csv-sep** *sep*\] \[*ca*\]  
Without a CA: a table of them, with their unit, the fields of their
certificate (country, state, locality, organization, ou, email),
policies and description.

**-a**  
Also the CAs you may only look at, not just the ones you may change.

**-z *N***  
How many CAs to print.

**--fields *F1,F2***  
Print these columns and no others, in the order they are named.

**--limit *N*, **--policy-limit** *N***  
How many policies to print per CA.

**--sort-by *field*, **--reverse****  
Which column to sort by, and the other way round.

**--raw, **--csv**, **--csv-sep** *sep***  
**--raw** leaves the header and the borders out, **--csv** prints one
row per line with **;** between the columns, and **--csv-sep** uses
another separator.

A column you may not see says **-**. With a CA named, this prints the
object itself instead of a table row, one value per line.

**show_oid** \[**--full**\] *ca*  
Show the OID of the CA: **ca\|\<realm\>/\<site\>/\<name\>**. With
**--full** the full OID, which names the unit as well:
**ca\|\<realm\>/\<site\>/\<unit_path\>/\<name\>**.  
Needs the ACL **view_public:object**.

**show_uuid *ca***  
Show the UUID of the CA.  
Needs the ACL **view_public:object**.

**list** \[**-a**\] \[**--attribute** *attribute*\] \[*pattern*\]  
List the CA names, and with a pattern only those that match it, see
**SELECTING OBJECTS** in **otpme**(1). You get the CAs you may change;
**-a** adds those you may only look at. **--attribute** matches the
pattern against that attribute instead of the name.

**touch *ca***  
Write the index entries of the CA again.  
Needs **touch**.

## Certificate Operations

**dump_cert *ca***  
The certificate of the CA, in PEM, to stdout. A certificate is public,
so this needs no ACL.

**dump_key** \[**-p** *passphrase*\] *ca*  
The private key of the CA to stdout. With **-p** it is encrypted with
that passphrase. Every call goes to the audit log.  
Needs the ACL **view:key**, or **view_all**. A plain **view** does not
open it.

**dump_ca_chain *ca***  
The certificates needed to check the certificate of the CA, to stdout:
those of the CAs that issued it, up to **REALM_CA**. For a **SITE_CA**
that is the certificate of **REALM_CA**, and that of the CA of the
parent site where there is one; for **REALM_CA** its own.

**create_client_cert** \[**--csr** *csr_file*\] \[**--valid** *days*\] \[**--key-len** *bits*\] \[**--country** *cc*\] \[**--state** *state*\] \[**--locality** *locality*\] \[**--organization** *org*\] \[**--ou** *ou*\] \[**--email** *email*\] *ca* *cn* *cert_out_file* \[*key_out_file*\]  
A client certificate signed by the CA, with the common name *cn*. It is
for a machine outside of OTPme that sends its backups to **backupd**,
see **BACKUP_CLIENT_CERT** in **otpme.conf**(5). The certificate goes to
*cert_out_file*. It is good for client authentication only, so it cannot
stand in for a host, a node or the site.

**--csr *csr_file***  
Sign this certificate request. Its common name must be *cn*, and its
subject is taken as it is. The key stays where the request was made, so
there is no *key_out_file*.  
Without **--csr** OTPme makes the key on the node and sends it along; it
goes to *key_out_file*, readable by you alone.

**--valid *days***  
How long the certificate is valid; the default is 365 days.

**--key-len *bits***  
The length of the key OTPme makes; the default is **cert_key_len** of
the CA, 4096 unless it is set.

**--country, **--state**, **--locality**, **--organization**, **--ou**, **--email****  
More fields of the subject. Not with **--csr**.

OTPme asks first; the global option **-f** skips the question.  
Needs the ACL **create_client_cert**.

**revoke *ca* *cert_file***  
Revoke a client certificate the CA made with **create_client_cert**. It
goes on the CRL of the CA, and the hosts and nodes get the new CRL with
the CA data of the realm.  
Only a client certificate the CA signed is taken; one that only carries
the name of the CA is refused. The certificate of a host, a node or the
site goes with its object, see **leave** in **otpme-tool**(1).  
OTPme asks first; the global option **-f** skips the question.  
Needs the ACL **revoke:cert**.

## CRL Management

A CA keeps a CRL, the list of the certificates it has revoked. The
master node signs it anew once a day, and the hosts and nodes get it
with the CA data of the realm. A revoked certificate stays on it until
30 days after it would have run out.

**crl_validity *ca* *days***  
How long a CRL is valid, in days: its next update is that far ahead. The
default is 3650.  
It must be 2 days at least, because the master node signs anew only once
a day, and a CRL past its next update is refused by every check. The CRL
is signed anew at once.  
OTPme asks first; the global option **-f** skips the question.  
Needs the ACL **edit:crl_validity**.

**dump_crl *ca***  
The CRL of the CA, in PEM, to stdout. A CRL is public, so this needs no
ACL.

**update_crl *ca***  
Sign the CRL anew now, without the certificates that ran out more than
30 days ago. The master node does this once a day itself.  
OTPme asks first; the global option **-f** skips the question.  
Needs the ACL **update_crl**.

## Configuration

A CA has these config parameters: **cert_key_len**, **cert_sign_algo**,
**crl_sign_algo**, **changelog** and **allow_changelog_clearing**, see
**CONFIG PARAMETERS**. A parameter is looked up at the CA, then at the
unit **cas**, then at the site.

**config** \[**-d**\] \[**-a**\] *ca* *parameter* \[*value*\]  
Set a parameter on the CA.

**-d**  
Remove the parameter from the CA, or with a value only that one value
from a list. It is not set back to a default: what applies afterwards is
what the unit or the site says.

**-a**  
Append the value to a parameter that holds a list, instead of replacing
what is there.

The ACL is per parameter, **set:config:\<parameter\>**.

**show_config *ca* \[*parameter*\]**  
The parameters set on the CA itself, or only the one named. Nothing is
shown for a parameter that the CA gets from its unit or from the site.

**get_config *ca* *parameter***  
What the parameter comes to for the CA, once the CA, its unit and the
site have been looked at. So this answers what applies, where
**show_config** answers what was set here.

**description *ca* \[*description*\]**  
Set the description. Without one OTPme asks and offers the current text
for editing. Needs **edit:description**.

**info** \[**--language** *LANG*\] *ca* \[*info*\]  
Set free-form info text. If *info* is omitted, the current info text is
opened in the editor named by the **EDITOR** environment variable. Needs
**edit:info**.  
Without **--language** the text is the administrator's own note. Nothing
shows the info of a CA to a user, so a text for a language stays a note
as well.

**dump_info** \[**--language** *LANG*\] *ca*  
Write one of those texts to stdout. **--language** picks which one;
without it you get the note of the administrator. Needs **view:info**.

## Object Changelog

Every change to the object writes an entry: who made it, when, and what
was done. A change can carry a comment of its own, through the global
option **--changelog**. Unless the **changelog** config parameter says
otherwise. It is read along the cascade (CA, unit, site), and nothing is
written where it is off. Without any value anywhere it is on.

An *entry_id* is the number the listing shows in front of an entry,
counted from 0.

Only the comment of an entry can be changed or removed. What was done
and by whom stays as it is.

A command that changes something asks first; the global option **-f**
skips the question.

**changelog *ca***  
Show the changelog of the CA, one entry per line: its *entry_id*, the
time, who made the change and what was done, then a detail in round
brackets and the comment in square brackets where there are any. Needs
the ACL **view:changelog**.

**edit_changelog *ca* *entry_id* *comment***  
Set the comment of that entry, or replace the one it has. That writes an
entry of its own. Needs the ACL **edit:changelog**.

**del_changelog *ca* *entry_id***  
Remove the comment of that entry. The entry itself stays, and an entry
without a comment is refused. That writes an entry of its own. Needs the
ACL **edit:changelog**.

**clear_changelog *ca***  
Remove every entry of the changelog. Afterwards it holds one entry: that
it was cleared.  
This needs more than the ACL **clear:changelog**: the config parameter
**allow_changelog_clearing** has to allow it (see **otpme**(7)). It is
true by default, but where no value is found at all, clearing is
refused. A value set on the token you are signed in with counts first.
Without one, the value of the CA counts, read along its cascade.

## Policy Management

A *policy* is the name of a policy, not a path. It is looked for in the
site of the CA. Which policies there are, and what each of them does, is
in **otpme-policy**(1).

One policy type fits a CA: **authonaction**, which asks for a login
again before the actions of the CA, see **AUTH ON ACTION HOOKS**.
**autodisable** names the CA among its types, but it is refused for
every object a realm or a site comes with, and those are the only CAs
there are.

Attaching and detaching ask before they change anything; the global
option **-f** skips the question.

**add_policy *ca* *policy***  
Attach a policy to the CA.  
A policy has a list of object types it is for; one that does not name
**ca** is refused. So is a second policy of a type that allows only one
per object, even when the first one is disabled, and a policy the CA
already has.  
Needs the ACL **assign:policy**.

**remove_policy *ca* *policy***  
Remove a policy from the CA.  
Needs the ACL **remove:policy**, and that one verbatim: a plain
**remove** does not cover it. Detaching a policy takes away what it
enforces, so it must not be cheaper than attaching one.

**list_policies** \[**--return-type** *TYPE*\] \[**--policy-types** *t1,t2*\] *ca*  
List the policies attached to the CA, the disabled ones too, marked
**(disabled)**. Use **--return-type** to select the attribute returned
(**name**, **read_oid**, **full_oid**, **uuid**); without it the names.
Only the names are marked. Use **--policy-types** to list only policies
of the given types; these are policy types, not policy names.  
Needs the ACL **view:policies**.

## ACL Management

An ACL says what somebody may do with this CA. The somebody is a role or
a token, never a user.

What the three forms **acl**, **+acl** and **++acl** mean is under
**ACLs** in **otpme**(7). Tab completion after **add_acl** offers the
ACLs a CA knows. A CA has no default ACLs, **+acl** and **++acl**:
nothing lies in a CA that could get them. It is not moved either, so
there is no ACL inheritance to switch.

Adding and removing ask first; the global option **-f** skips the
question.

**add_acl *ca* *owner_type* *owner* *acl*\[:*value*\]\[,*acl*\[:*value*\]\]**  
Give a role or a token one or more ACLs on this CA.  
*owner_type* is **role** or **token**. *owner* names it the way
**list_acls** prints it: a role as *site/name*, or by its name alone on
its own site; a token as *user/token*. An ACL can carry a value, for
example **view:key**. To give several ACLs at once, separate them with
commas: **create_client_cert,revoke:cert**.  
Needs the ACL **add:acl**.

**del_acl *ca* *acl*\[,*acl*\]**  
Take those ACLs away again.  
Here an *acl* is the whole entry, owner and all, the way **list_acls**
prints it: **role:berlin/backupadmins:create_client_cert**.  
Needs the ACL **delete:acl**.

**list_acls *ca***  
Show the ACLs that lie on this CA, i.e. who may do what with it.  
Needs the ACL **view:acl**.

## Export and Cleanup

**export** \[**--password** *password*\] *ca*  
Write the whole object of the CA to stdout, as JSON: its certificate,
its private key, its CRL and the certificates it has revoked, its ACLs,
policies, config parameters and the rest. **otpme-tool import** reads it
back.  
The private key is in it. **--password** encrypts the secret values with
that password; without it they are only hex encoded, so in clear. Every
export goes to the audit log.  
Needs the ACL **export**. This alone hands out the private key, as
**view:key** does for **dump_key**.

**remove_orphans *ca***  
Remove references to objects that are gone: orphan ACLs and policies of
the CA.  
It asks once for what it found; the global option **-f** skips the
question.  
Needs the ACL **remove:orphans**.

# OPTIONS

Every option belongs to one command and is described with that command
above.

Global options work with every command, see **otpme**(1).

# CONFIG PARAMETERS

A CA takes these. What each of them does, and how a parameter is
resolved, is in **otpme**(7).

**cert_key_len (int, default: 4096)**  
The length of the key of a certificate the CA makes the key for: one of
**create_client_cert** without **--key-len**, and a server, host or node
certificate made without a request. 2048, 3072, 4096 or 8192.

**cert_sign_algo (str, default: sha256)**  
The hash the CA signs certificates with: **sha256**, **sha384** or
**sha512**.

**crl_sign_algo (str, default: sha256)**  
The hash the CA signs its CRL with, the same values.

**changelog (bool, default: true)**  
Whether the commands on this CA are written to its changelog.

**allow_changelog_clearing (bool, default: true)**  
Whether that changelog may be cleared.

# EXAMPLES

## A client certificate for a backup client

**otpme-ca create_client_cert SITE_CA backup1.example.org backup1.pem backup1.key**  
A machine outside of OTPme gets a certificate to send its backups to
**backupd**, valid for a year. OTPme makes the key.

**openssl req -new -newkey rsa:4096 -nodes -subj /CN=backup1.example.org -keyout backup1.key -out backup1.csr**  
**otpme-ca create_client_cert --csr backup1.csr SITE_CA backup1.example.org backup1.pem**  
The same with a request made on the machine: the key does not leave it.

**otpme-ca revoke SITE_CA backup1.pem**  
When the machine is gone, or its key got out.

## Checking a certificate

**openssl verify -CAfile \<(otpme-ca dump_cert SITE_CA; otpme-ca dump_ca_chain SITE_CA) backup1.pem**  
Whether **SITE_CA** issued the certificate, checked up to **REALM_CA**.

## The CRL

**otpme-ca dump_crl SITE_CA \| openssl crl -noout -text**  
What the CA has revoked, and until when the CRL is valid.

**otpme-ca crl_validity SITE_CA 30**  
The CRL is valid for 30 days from now on; it is signed anew at once.

## Letting a role make client certificates

**otpme-ca add_acl SITE_CA role backupadmins create_client_cert,revoke:cert**  
The role **backupadmins** may make client certificates and revoke them.

# AUTH ON ACTION HOOKS

An auth on action policy can ask for a login again before these actions.
See **Auth On Action Policy** in **otpme-policy**(1). A ca has the hooks
every object type has, and these; a command of another name is in
brackets:

> create_ca_cert, create_cert, create_client_cert, create_server_cert,
> revoke_cert, set_config_parameter (config), set_crl, update_crl.

# FILES

*/var/lib/otpme/tree/*  
The objects of the realm, on the nodes and, by sync, on the hosts. A CA
is the directory *\<name\>.ca* in the unit **cas** of its site, e.g.
*\<realm\>.realm/\<site\>.site/cas.unit/SITE_CA.ca/*, with its settings
in *object.json*. Change them with the commands above, not in the file.

*/etc/otpme/ssl/ca.pem*  
The certificates and CRLs of **REALM_CA** and of every **SITE_CA**, the
CA data of the realm. Every host and node checks the certificates of the
others against it. OTPme writes it anew when a CA or its CRL changes.

# SEE ALSO

**otpme**(1), **otpme**(7), **otpme.conf**(5), **otpme-site**(1),
**otpme-host**(1), **otpme-node**(1), **otpme-tool**(1),
**otpme-backup**(1), **otpme-policy**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
