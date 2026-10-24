# NAME

otpme-site - add the sites of a realm and say how each of them is
reached, trusted and signed for

# SYNOPSIS

**otpme-site** *command* \[*options*\] \[*site*\]

# DESCRIPTION

A site is a part of a realm with its own administration, usually one per
location. It has its own nodes, which form a cluster, its own CA, and
its own units, roles, policies and clients. Users and groups belong to
one site and are known in all of them.

The site object is what this command works on. It holds how the site is
reached — an address and the names for logins, for management and for
the SSO portal — and what it proves itself with: its certificate and
key, the certificates of the portal and of RADIUS, the signing keys of
the OIDC provider and a handful of secrets. It also holds which other
sites it trusts, and it is the last place a config parameter is looked
for, so what is set on it holds for everything in the site that says
nothing of its own.

A realm has one master site. Sites are added and deleted there, and
every other site is a slave site, or a sub site of the site it was added
on.

**A site is changed on the site itself.** Every site has a copy of the
others, and the sync brings the values of each site back to its copies.
So on a site that is not your own only what your site decides about that
one can be set: its description, whether it is enabled, and whether your
site authenticates and syncs with it.

For the bigger picture — realms, sites, sub sites, how a login runs
across them — see **otpme**(7).

# COMMANDS

## Site Management

**add \[*options*\] *site* *node_name* *site_fqdn* \[*site_address*\]**  
Create a site, and with it its CA, its base objects and the object of
its first node.  
The name is stored in lower case. A site is added on the master site of
the realm. The one exception is a name that starts with the name of your
own site and a dot, like **berlin.files** on **berlin**: that makes a
sub site of the site you are on.  
*node_name* is the first node of the site, its master node. Only the
object is created here; the machine itself still has to join, see
**otpme-tool**(1). The site is created disabled, and it is enabled when
that node has joined. A name a host or a node of the new site already
has is refused.  
*site_fqdn* becomes the auth, the management and the SSO FQDN of the
site. **auth_fqdn**, **mgmt_fqdn** and **sso_fqdn** change each of them
on its own afterwards.  
*site_address* is the floating address of the site, the one its cluster
answers on. Without it the address is looked up in DNS under
*site_fqdn*; a name with more than one address is refused, and so is one
with none.  
**--trust *site1***,***site2*** names the sites the new site trusts, so
the trusts need not be added one by one afterwards (see **add_trust**).
A name that belongs to no site is refused before anything is created.  
The other options are under **ADD OPTIONS**.  
Needs the ACL **add:site** on the realm, not on the site — there is none
yet.

**del \[**--no-trash**\] *site***  
Delete a site and every object in it. All of it goes to the trash, from
where **otpme-trash**(1) can bring it back; **--no-trash** deletes it
right away, the objects as well.  
A site is deleted on the master site of the realm, and a sub site also
on the site it belongs to. Your own site cannot be deleted.  
Asks first; the global option **-f** skips the question.  
Needs the ACL **delete:object**.

**show \[**-a**\] \[**-z** *N*\] \[**--fields** *F1,F2*\] \[**--limit** *N*\] \[**--policy-limit** *N*\] \[**--sort-by** *field*\] \[**--reverse**\] \[**--raw**\] \[**--csv**\] \[**--csv-sep** *sep*\] \[*site*\]**  
Without a site: a table of all of them, with their status, their
version, whether authentication and synchronization with them are on,
the sites they trust, their address, their three FQDNs, their policies
and their description.  
The status is **Master** for the master site of the realm, **Sub** for a
sub site and **Slave** for every other one; a **(D)** behind it says the
site is disabled.  
The version is the OTPme version the site was last brought up to with
**upgrade**. It is empty for a site that was not brought up to one yet.

**-a**  
Also the sites you may only look at, not just the ones you may change.

**-z *N***  
How many sites to print.

**--fields *F1,F2***  
Print these columns and no others, in the order they are named. The
names are the ones in the header of the table. A name with a **+** in
front is added to the columns that are shown anyway, and one with a
**-** is left out of them.

**--limit *N*, **--policy-limit** *N***  
How many policies to print per site.

**--sort-by *field*, **--reverse****  
Which column to sort by, and the other way round.

**--raw, **--csv**, **--csv-sep** *sep***  
For reading with something other than your eyes: **--raw** leaves the
header and the borders out, **--csv** prints one row per line with **;**
between the columns, and **--csv-sep** uses another separator.

A column you may not see says **-**. Which ACL opens which column is the
**view:** ACL of that value, and the ACL that sets the same value does
as well — whoever may set a thing may read it.  
With a site named, this prints the object itself instead of a table row:
one value per line, and with them what the table leaves out — the
certificates, the secrets, the CA, the admin role and the SSO hosts. A
value you may not see is left empty. That needs the ACL
**view_public:object**.

**list \[**-a**\] \[**--attribute** *attribute*\] \[*regex*\]**  
List the site names, and with a regex only those that match it. You get
the sites you may change; **-a** adds those you may only look at.  
**--attribute** matches the regex against that attribute instead of the
name.

**enable *site***  
Enable a disabled site.  
Needs the ACL **enable:object**.

**disable *site***  
Switch a site off without deleting it. The nodes of your site stop
contacting it, and the master site of the realm no longer hands it out
to the other sites.  
Needs the ACL **disable:object**.

Both ask first, and both work on a site that is not your own. That is
rare on this page: a site is changed on the site itself, and from
anywhere else all but a few commands are refused.

**touch *site***  
Re-index the object to fix potential index problems.  
Needs the ACL **touch**.

## Site Configuration

A site is changed on the site itself. From another site only a few
things can be set, the ones that say how your site deals with that one:
**description**, **enable** and **disable**, **enable_auth** and
**disable_auth**, **enable_sync** and **disable_sync**. And **touch**,
which changes nothing: it only builds the index of your copy anew.
Everything else is refused there, because the next sync would bring the
site's own values back.

The three commands that change how the site is reached ask first; the
global option **-f** skips the question.

**address *site* *ip_address***  
Change the address of the site. This is the floating address: the node
that is master of the cluster holds it, and it moves with that role.  
The address is taken as it is given; nothing checks that it is one.  
Needs the ACL **edit:address**.

**auth_fqdn *site* *fqdn***  
Change the name the hosts of the site connect to for a login.  
Needs the ACL **edit:auth_fqdn**.

**mgmt_fqdn *site* *fqdn***  
Change the name the management commands connect to. A new management
certificate is made for that name, signed by the CA of the site; it is
the one the LDAP server of the site shows.  
Needs the ACL **edit:mgmt_fqdn**.

Both names start out as the *site_fqdn* of **add**. A host looks the
name up in DNS, so a name that is changed here has to be there first.
The third name, the one of the SSO portal, is **sso_fqdn** below.

**config \[**-d**\] \[**-a**\] *site* *parameter* \[*value*\]**  
Set a parameter on the site.  
A config parameter is looked for on the object, then on the units above
it, then on the site, and the first value found applies. So what is set
here is what holds for everything in the site that says nothing of its
own. A site can turn that around for a parameter it names in
**force_site_config_parameters,** and then its own value wins (see
**otpme**(7)).

**-d**  
Remove the parameter from the site, or with a value only that one value
from a list. It is not set back to a default: the site is where the
search ends, so nothing is found any more. **upgrade** brings it back
with its default.

**-a**  
Append the value to a parameter that holds a list, instead of replacing
what is there.

Without a *value* the parameter is set to its default.  
The ACL is per parameter, **set:config:***parameter*.

**upgrade \[**--all**\] \[**--procs** *NUM*\] *site***  
Bring the site up to the OTPme version its nodes run. Run it after an
update, when all nodes of the site run the new version. It does two
things.

It adds the config parameters the site is missing, with their defaults.
A site gets every parameter when it is created, so one that a later
OTPme version brings is not on an older site until this is run. A
parameter that is already set is not changed.

It stores the objects of the site in the format of the new version. A
new version may store an object in another way. The command writes every
object that is still in the old format. The first run on a site writes
every object once, and can take a while.

The site is in maintenance until this is done, see **Maintenance**
below. While the command runs it switches maintenance on, so nothing
else is changed in between. When it is done, the site is at the version
of its nodes and maintenance ends. Maintenance that was switched on with
**maintenance on** stays on.

The command does not start while a node of the site is offline or runs
another version; it says which node. A disabled node does not count. If
the command fails or is cut short, the site stays in maintenance. Run it
again; it goes on where it stopped.

**--all**  
Look at every object, and not only at those that are known to be in the
old format. Use it after objects came in from an old backup.

**--procs *NUM***  
Write the objects with *NUM* processes. Without it a quarter of the CPU
cores is used, so the node can still answer logins. Fewer than 500
objects of a kind are written without extra processes.

Run it on a node or host of the site; the master node of the site
carries it out.  
Needs the ACL **set:config**, for all parameters and not just one.

**show_config *site* \[*parameter*\]**  
The config parameters set on the site, or only the one named.  
Nothing is shown for a parameter whose ACL **view:config:***parameter*
you do not hold. The settings of the site — its address, its names, its
certificates and secrets — are not config parameters: **show** and
**export** are where those are.

**get_config *site* *parameter***  
The value of one parameter.  
Needs the ACL **view:config:***parameter*, the same one that opens it in
**show_config**.

**description *site* \[*description*\]**  
Set the description. Without one OTPme asks and offers the current text
for editing.  
Needs the ACL **edit:description**.

**info \[**--language** *LANG*\] *site* \[*info*\]**  
Set free-form info text. If *info* is omitted, the current text is
opened in the editor named by the **EDITOR** environment variable.  
Without **--language** the text is the administrator's own note about
the object, which no user is ever shown. With a language it is text for
the users in that language.  
Needs the ACL **edit:info**.

**dump_info \[**--language** *LANG*\] *site***  
Print the info text, of that language or the administrator's own.  
Needs the ACL **view:info**.

## Maintenance

A site is in maintenance while nothing in it may be changed. That is the
case

-   when its nodes run another OTPme version than the one the site was
    last brought up to. Only the first two numbers count: 0.3.1 and
    0.3.4 are the same version here, 0.4.0 is not.

-   when its nodes store objects in another format than the site does,

-   when it was switched on with **maintenance on**, or by **upgrade**
    while that runs or after it failed.

So an update of OTPme puts the site into maintenance by itself, and
**upgrade** ends it. Nothing is written to start it: each node compares
the code it runs with the site. The master node is the one that counts,
because it writes the objects.

While the site is in maintenance:

-   No object of the site is added, changed, renamed or deleted. A
    command that would do it fails and says so.

-   Logins go on. Sessions and the other data of a login are written as
    usual.

-   The SSO portal shows a notice. Settings and the profile can be
    looked at, but not changed. A login token cannot be set up, and an
    account cannot be recovered.

-   An object that is due to be disabled automatically counts as
    disabled. It is written as disabled when maintenance ends.

-   The jobs that write objects wait: the CRL update, auto-disable,
    resolvers, tree jobs, the nsscache sync on the nodes, and backups.
    They run again when maintenance ends.

-   No host or node can join.

-   What the other nodes and sites send is still taken in.

**maintenance *site* \[**on**\|**off**\|**status**\]**  
Switch maintenance on or off, or say why the site is in maintenance.

**status**  
Say whether the site is in maintenance on its master node, and why. This
is the default.  
Needs the ACL **view:maintenance**.

**on**  
Switch maintenance on, for example for work on the site.  
Needs the ACL **enable:maintenance**.

**off**  
Switch maintenance off, whoever switched it on. If the site stays in
maintenance for another reason, the command says so.  
Needs the ACL **disable:maintenance**.

**on** and **off** ask first; the global option **-f** skips the
question.  
Run the command on a node or host of the site; the master node of the
site carries it out.

## Trust Relationships

A site that trusts another one hands it its token secrets. The users and
tokens of a site are known in every site of the realm, but their secrets
stay at home. If **berlin** trusts **munich**, the secrets of berlin are
synced to the nodes of munich, and munich checks the login of a berlin
user itself. Without the trust munich has no secrets of berlin and sends
such a login on to berlin, so it only works while berlin can be reached.

A trust goes one way. That berlin trusts munich says nothing about the
secrets of munich; for those munich has to trust berlin.

A trust is set on the site that trusts, and only there: *site* has to be
your own site. Both commands ask first; the global option **-f** skips
the question.

This trust is not what the config parameters ending in **\_trusts**
name. Those are lists of their own, each for one thing, see
**otpme**(7).

**add_trust *site* *trusted_site***  
Let *site* trust *trusted_site*. A name that belongs to no site is
refused, and so is the site itself and a site that is trusted already.  
Needs the ACL **add:trust**.

**del_trust *site* *trusted_site***  
Take the trust away again. Takes a UUID as well, so a site that was
deleted while it was trusted can still be taken off the list.  
Needs the ACL **delete:trust**.

The sites a site trusts are in the **Trusts** column of **show** and in
the object itself; the ACL **view:trusts** opens them, and so do the two
above.

## Authentication and Synchronization

Two switches per site, both on by default. They are settings of your
site about the site that is named, so they also work on a site that is
not your own, and what berlin sets about munich holds in berlin only.
The sync between the sites leaves them as they are.

All four commands ask first; the global option **-f** skips the
question. The **Auth** and **Sync** columns of **show** say how the
switches stand.

**disable_auth *site***  
Stop logins.  
With another site named, the users of that site are no longer let in on
your site.  
With your own site named, nobody is let in on it any more, whichever
site the user is from.  
An admin is let in either way, and a logout still works.  
Needs the ACL **disable:auth**.

**enable_auth *site***  
Allow logins again.  
Needs the ACL **enable:auth**.

**disable_sync *site***  
Stop the sync with another site. The nodes of your site no longer fetch
from it and no longer tell it about changes, and a node of that site
that asks yours is refused.  
Your own site cannot be named here.  
Needs the ACL **disable:sync**.

**enable_sync *site***  
Sync with the site again.  
Needs the ACL **enable:sync**.

**disable** goes further than both: a site that is disabled is not
contacted at all.

## Certificate Management

A site has a certificate and a key of its own, signed by the CA of the
site. With the key the site signs what it tells other sites, for example
the answer to a login that was sent on to it, and the other sites check
that with the certificate.

Every node and every host keeps the certificates of the sites it knows,
those of other sites as well, in */etc/otpme/ssl/*realm*-*site*.pem*.
What is in that file is not replaced by the sync. The certificate is
pinned there on purpose: a host goes on trusting the one it has,
whatever it is told later. A host that joins can be told the fingerprint
to expect, see **--check-site-cert** in **otpme-tool**(1).

This is not the certificate of the SSO portal, of RADIUS or of the
management name; those have sections and commands of their own.

**dump_cert *site***  
Print the certificate of the site. A certificate is public, so no ACL of
its own is asked for.

**dump_key \[**-p** *passphrase*\] *site***  
Print the private key of the site. With **-p** it is encrypted with that
passphrase, which then stands on the command line for others on the
machine to see.  
Needs the ACL **view_all:cert_key**.

**dump_ca_chain *site***  
Print the CA certificates the certificate of the site is checked with,
up to the CA of the realm. No ACL of its own is asked for.

**renew_cert *site***  
Make a new key and a new certificate for the site. The old certificate
is revoked.  
No node and no host takes the new one by itself, because the old one is
pinned. After a renewal, run this on every node and every host, in the
other sites as well:

> **otpme-tool sync --request-site-cert sites**

Asks first; the global option **-f** skips the question.  
Needs the ACL **renew:cert**.

**site_cert *site* *cert_file***  
Put the certificate from that file in the place of the one the site has.
The key stays, and nothing checks that the two belong together. The
nodes and hosts keep the old one here too, until they are told to fetch
it as under **renew_cert**.  
Asks first; the global option **-f** skips the question.  
Needs the ACL **edit:site_cert**.

## RADIUS Certificate

The RADIUS server of a site needs a certificate for the EAP methods that
open a TLS tunnel, which is what 802.1X on a switch or an access point
uses. Without anything set here it shows the certificate of the site,
with the key of the site and the CA certificates of the realm.

That works for devices that were given the CA of the realm and that
expect the name of the site in the certificate. A certificate of its own
is for the others: one with a name just for RADIUS in it, or one from a
CA the devices already know.

Each of the three can be set on its own, and what is not set stays what
it was above. All three take a file in PEM format. Without a file the
value is taken away again and RADIUS goes back to the one of the site.

The RADIUS server is reloaded on every node of the site after a change.
While the certificate and the key it would get do not fit each other, it
is not reloaded and goes on with what it had, and the command says so.
That is also the case for a certificate that is set without its key: it
would be paired with the key of the site. So set the two in one call,
with **--key**, and do not leave a pair that does not fit: the next
start of RADIUS would get it.

All three commands ask first; the global option **-f** skips the
question.

**radius_cert \[**--key** *key_file*\] \[**--ca-cert** *ca_cert_file*\] *site* \[*cert_file*\]**  
Set the certificate the RADIUS server shows.  
**--key** sets the key that belongs to it in the same call, and
**--ca-cert** the CA certificates.  
Needs the ACL **edit:radius_cert**, and for what is given with it the
ACL of that as well: **edit:radius_key** for **--key** and
**edit:radius_ca_cert** for **--ca-cert**.

**radius_key *site* \[*key_file*\]**  
Set the key of that certificate.  
Needs the ACL **edit:radius_key**.

**radius_ca_cert *site* \[*ca_cert_file*\]**  
Set the CA certificates the RADIUS server is given.  
Needs the ACL **edit:radius_ca_cert**.

**show** *site* prints the three as **RADIUS_CERT**, **RADIUS_KEY** and
**RADIUS_CA_CERT**, each to whoever holds its **view:** ACL.

## SSO Configuration

The SSO portal is the web page users sign in on, and the OIDC provider
behind it. It runs on every node and host of the site that has
**SSO_SERVER="True"** in */etc/otpme/otpme.conf*, see **otpme.conf**(5);
a host has to be made an SSO host first, see **add_sso_host** below.

What the portal needs from the site is its name, a certificate and a key
for that name, and two secrets. A site has all of them from the start:
the certificate is made by the CA of the site, the secrets are random.

All of this is set on your own site, and the commands that change
something ask first; the global option **-f** skips the question.

**sso_fqdn *site* *fqdn***  
Change the name of the portal. It is the name in the address users open,
and the issuer of the OIDC provider is built from it, so the
applications that sign in through it have to be told as well.  
A new certificate and key are made for that name, by the CA of the site,
and they **replace** the ones that are set. A certificate of your own
has to be set again afterwards.  
Needs the ACL **edit:sso_fqdn**.

**sso_cert \[**--key** *key_file*\] *site* \[*cert_file*\]**  
Set the certificate the portal shows, from a file in PEM format. The one
the site makes itself is from a CA no browser knows, so this is where a
public one goes.  
**--key** sets the key that belongs to it in the same call. A
certificate and a key that do not fit each other are stored, and the
command says so: the portal keeps the pair it has when it is reloaded,
and does not start with the new one.  
The portal takes a new pair when it is reloaded, on each machine it runs
on:

> **otpme-controld reload httpd**

  
Without a file the certificate is taken away, and nothing is put in its
place.  
Needs the ACL **edit:sso_cert**, and **edit:sso_key** as well for
**--key**.  
Pass the **full chain**, not the leaf certificate alone: the file may
hold the certificate followed by every CA certificate needed to
establish it, and that is what gets served. With Let's Encrypt that
means *fullchain.pem*, not *cert.pem*.  
A leaf on its own usually still works in a browser, which caches
intermediates or fetches them over the certificate's AIA extension.
Mobile apps do neither: they abort the handshake, and the server logs it
as the peer's alert **SSLV3_ALERT_CERTIFICATE_UNKNOWN** - which reads
like a server fault but is the client refusing the chain. To see what is
actually served:

openssl s_client -connect *sso_fqdn*:443 -servername *sso_fqdn*
-showcerts \</dev/null \| grep -c 'BEGIN CERTIFICATE'

**sso_key *site* \[*key_file*\]**  
Set the key of that certificate, from a file in PEM format. Without a
file the key is taken away.  
Needs the ACL **edit:sso_key**.

**sso_secret *site* *secret***  
Change the secret the portal signs its session cookies with. Every
session of the portal that is open becomes invalid, and the users have
to sign in again.  
Needs the ACL **edit:sso_secret**.

**sso_csrf_secret *site* *secret***  
Change the secret the portal protects its forms with. A form that is
open in a browser has to be loaded again.  
Needs the ACL **edit:sso_csrf_secret**.

Both secrets are given on the command line, where others on the machine
can see them, and neither command makes one up. The portal reads them
when it starts.

**add_sso_host *site* *host_name***  
Make a host an SSO host.  
A node has everything of its site and can run the portal as it is. A
host has not: it gets no key and no secret of the site. An SSO host is
the exception, and is synced what the portal needs:

SSO_CERT, SSO_KEY  
The certificate the portal shows, and its key.

SSO_SECRET  
The secret the session cookies are signed with.

SSO_CSRF_SECRET  
The secret the forms are protected with.

With them come the config parameters of the site that the portal reads
itself.

The host has to be a host of this site; a node cannot be named, and
needs no naming. To start the portal on it, set **SSO_SERVER** as above.

Needs the ACL **add:sso_host**.

**remove_sso_host *site* *host_name***  
Take the host off the list again. It is no longer synced what is listed
above; the host itself stays as it is.  
Takes a UUID as well, so a host that was deleted while it was an SSO
host can still be taken off the site.  
Needs the ACL **remove:sso_host**.

**sso_logo *site* *image_file***  
Set the logo the portal of this site shows on its login and recovery
pages. PNG or JPEG, at most 512 KiB — it is part of the site object,
which every node and host of the realm syncs. A site without a logo
shows the OTPme logo the portal comes with. The tiqr app shows the same
logo for the accounts enrolled here.  
Needs the ACL **add:sso_logo**.

**dump_sso_logo *site***  
Print the logo as base64.  
Needs the ACL **dump:sso_logo**.

**del_sso_logo *site***  
Remove the logo, so the portal shows the default one again.  
Needs the ACL **delete:sso_logo**.

**tiqr_secret *site* \[*secret*\]**  
Change the secret the tiqr logins of the portal are made with. Without
*secret* a new one is made, 64 hex characters; give one only to bring a
known value back.  
The challenge and the poll id of a tiqr login are made from it, and both
live for **tiqr_challenge_expiry** seconds. So a change breaks the
logins that are under way at that moment and nothing else: the phones
that are enrolled, their token secrets and the sessions stay. That is
why this one does not ask.  
Needs the ACL **edit:tiqr_secret**.

## OIDC OpenID Connect Provider

OTPme can act as an OpenID Connect Provider (OP) per site. The OP is
**site-local**: each site exposes its own discovery document at
*https://{site.sso_fqdn}/oidc/.well-known/openid-configuration* with
*issuer = https://{site.sso_fqdn}/oidc*. Each OIDC client object lives
on exactly one site, and a Relying Party must address the issuer of that
site to authenticate against it.

Sites in the same realm do not share OIDC clients, signing keys, or
pairwise secrets -- each site is its own OP. For high availability
within one site, use multiple SSO hosts (see **add_sso_host**) behind a
load balancer or DNS round-robin; they all serve the same issuer and
share the necessary site data via SSO-host sync. For genuinely separate
OPs, run OIDC on each site individually with its own clients.

Supported flow: only the OAuth 2.1 **Authorization Code Flow with** PKCE
is implemented (response_type=code, grant_type=authorization_code +
refresh_token). The legacy **Implicit Flow** (response_type=id_token) is
intentionally not supported: what comes back through the URL fragment
leaks through browser history, referrers, XSS and extensions. OAuth 2.1
§10.1 drops the implicit grant for that reason, following RFC 9700
§2.1.2, although both speak of **response_type=token** and leave the
OIDC **id_token** response types to OIDC; not implementing them is this
implementation's own decision. Modern SPAs should use Code+PKCE instead.
The **Hybrid Flow** (response_type="code id_token") is likewise not
supported; its only marginal benefit (immediate identity rendering
before the /token call) does not justify the additional fragment-based
delivery surface. PKCE is mandatory by default
(**oidc_pkce_required=True**) and only **S256** is advertised in
discovery; **plain** can be enabled per client for legacy interop but is
never advertised (see **oidc_allow_plain_pkce**).

The commands below ask first, except for **show_oidc_keys**; the global
option **-f** skips the question.

**enable_oidc *site***  
Switch the OIDC provider of the site on. A signing key is made if the
site has no active one, and a pairwise secret if it has none.  
Needs the ACL **enable:oidc**.

**disable_oidc *site***  
Switch the OIDC provider off. The keys and the pairwise secret stay, so
switching it on again goes on where it stopped.  
Needs the ACL **disable:oidc**.

**renew_oidc_key \[**--key-type** *preset*\] \[**--kty** *RSA\|EC\|OKP*\] \[**--size** *N*\] \[**--alg** *alg*\] *site***  
Make a new signing key and sign with it from now on. The key that was
active becomes **retired**: nothing is signed with it any more, but it
stays published, so what it signed can still be checked.  
It stays published for as long as the config parameter
**oidc_retired_max_age** says, two hours by default (see **otpme**(7)).
After that it is no longer handed out, and the next run of this command
removes it.  
Without an option the key is RSA with 2048 bits, signing with RS256.

**--key-type *preset***  
One of **rsa** (2048 bits), **rsa-3072**, **rsa-4096**, **ec** and
**ec-p256** (the same), **ec-p384**, **ec-p521**, **ed25519**. The
algorithm comes with the preset. Not together with the three below.

**--kty *RSA\|EC\|OKP*, **--size** *N*, **--alg** *alg***  
The same by hand: the key type, the bits of an RSA key or the name of
the curve (**P-256**, **P-384**, **P-521**, **Ed25519**), and the
algorithm (**RS256**, **RS384**, **RS512**, **ES256**, **ES384**,
**ES512**, **EdDSA**). Without **--alg** the algorithm is the one that
goes with the key, and one that does not fit the key is refused.

Needs the ACL **renew:oidc_key**.

**revoke_oidc_key *site* *kid***  
Remove a signing key at once, for a key that got out. It is no longer
published, so everything it signed stops being accepted. If it was the
active key, a new one is made in its place.  
Needs the ACL **revoke:oidc_key**.

**show_oidc_keys *site***  
Print the signing keys of the site, the active one and the retired ones,
each under its *kid*.  
This prints the keys whole, **the private parts included**.  
Needs the ACL **view_all:oidc_keys**. A plain **view** does not open it;
**view:oidc_keys** does, because it names these keys.

**oidc_pairwise_secret *site* \[*secret*\]**  
Change the secret the pairwise *sub* of a user is made from. Without
*secret* a new one is made, 64 hex characters; give one only to bring a
known value back.  
**Every pairwise sub changes with it.** An application that knows its
users by their *sub* sees a new user at the next login, so talk to each
of them before.  
Needs the ACL **edit:oidc_pairwise_secret**.

The config parameters of OIDC are **oidc_pkce_required**,
**oidc_allow_plain_pkce**, **oidc_logout_scope**,
**oidc_require_consent**, **oidc_default_scopes**,
**oidc_email_attribute** and **oidc_retired_max_age**. What they do is
in **otpme**(7), and how an application is registered in
**otpme-client**(1).

## Cluster

The nodes of a site form a cluster, and the cluster key is what a node
shows another one when it connects to its cluster daemon. A node that
shows another key is turned away. A site gets a random key when it is
created, and there is rarely a reason to change it.

**cluster_key *site* *cluster_key***  
Set the cluster key. It is given on the command line, where others on
the machine can see it, and is not made up for you.  
**A node that does not get the new key drops out of the cluster.**  
Asks first; the global option **-f** skips the question.  
Needs the ACL **edit:cluster_key**.

## FIDO2 CA Certificates

A FIDO2 or U2F key carries an attestation certificate that says who made
it. Where the config parameter **check_fido2_attestation_cert** or
**check_u2f_attestation_cert** is on, a key is only taken when that
certificate is valid and was signed by one of the CA certificates kept
here (see **otpme**(7)).

The CA certificate is found by its subject: it has to be the one the
attestation certificate names as its issuer. A CA further up does not
count, so add the certificate that signed the keys themselves.

A site has none of them at first. With the check on and no certificate
for the maker of a key, that key is refused.

**add_fido2_ca_cert *site* *ca_cert_file***  
Add a CA certificate from a file in PEM format. A file that is no
certificate is refused, and so is one whose subject the site already
has.  
Asks first; the global option **-f** skips the question.  
Needs the ACL **add:fido2_ca_cert**.

**del_fido2_ca_cert *site* *subject***  
Remove a CA certificate. The *subject* has to be written as
**list_fido2_ca_certs** prints it, and in quotes where it holds spaces.
Keys that are deployed stay as they are; the check is made when a key is
deployed.  
Asks first; the global option **-f** skips the question.  
Needs the ACL **delete:fido2_ca_cert**.

**list_fido2_ca_certs *site***  
Print the subjects of the CA certificates of the site, one per line.  
Needs the ACL **view:fido2_ca_cert**.

## Password Members

The config parameter **password_store_members** of the site names who
gets the keys of the passwords, where no unit sets it, see
**otpme-pass**(1). The members count only when a user signed them. The
commands are the same as for a unit, see **otpme-unit**(1).

**sign_password_members *site***  
Sign the members with your sign key.

**show_password_members *site***  
Show the members, the users they stand for, and each signature.

**unsign_password_members \[**--signer** *user*\] *site***  
Remove your signature, or with **--signer** the one of that user.

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

**changelog *site***  
Show the changelog of the site. Needs the ACL **view:changelog**.

**edit_changelog *site* *entry_id* *comment***  
Set the comment of that entry, or replace the one it has. Needs the ACL
**edit:changelog**.

**del_changelog *site* *entry_id***  
Remove the comment of that entry. The entry itself stays, and an entry
without a comment is refused. Needs the ACL **edit:changelog**.

**clear_changelog *site***  
Remove every entry of the changelog.  
This needs more than the ACL **clear:changelog**: the config parameter
**allow_changelog_clearing** has to allow it (see **otpme**(7)). It is
true by default, but where no value is found at all, clearing is
refused. OTPme asks the token you are signed in with first, then the
object.

## Policy Management

A *policy* is the name of a policy, not a path. It is looked for in that
site itself, not in the site you are on. Which policies there are, and
what each of them does, is in **otpme-policy**(1).

Attaching and detaching ask before they change anything; the global
option **-f** skips the question.

**add_policy *site* *policy***  
Attach a policy to the site.  
A policy has a list of object types it is for; one that does not name
**site** is refused. So is a second policy of a type that allows only
one per object.  
Needs the ACL **assign:policy**.

**remove_policy *site* *policy***  
Remove a policy from the site.  
Needs the ACL **remove:policy**, and that one verbatim: a plain
**remove** does not cover it. Detaching a policy takes away what it
enforces, so it must not be cheaper than attaching one.

**list_policies \[**--return-type** *TYPE*\] \[**--policy-types** *t1,t2*\] *site***  
List the policies attached to the site. Use **--return-type** to select
the attribute returned (**name**, **read_oid**, **full_oid**, **uuid**).
Use **--policy-types** to list only policies of the given types; these
are policy types, not policy names.  
Needs the ACL **view:policies**.

## ACL Management

An ACL says what somebody may do with this site. The somebody is a role
or a token, never a user.

A site is also the top of everything in it, so it is where an ACL for
all of it is set. A normal ACL is for the site object alone. A default
ACL, **+acl** or **++acl**, is not for the site: it is handed down to
the units of the site and from there to the objects it names. What the
three forms mean, and which ACLs exist, is under **ACLs** in
**otpme**(7) and in **otpme-acls**(7).

Adding and removing ask first, once for the whole command; the global
option **-f** skips the question.

**add_acl \[**-r**\] \[**-a**\] \[**--objects** *types*\] \[**--procs** *num*\] *site* *owner_type* *owner* *acl*\[:*value*\]\[,*acl*\[:*value*\]\]**  
Give a role or a token one or more ACLs on this site.  
*owner_type* is **role** or **token**, and *owner* the path of that role
or token. An ACL may carry a value, for example **view:trusts**, and
several are separated by commas.  
Without an option only the site is changed. A default ACL then reaches
what is created from now on, and nothing that is already there.

**-a**  
Hand a default ACL down to what is already there. The units at the top
of the site get it, and the objects in those units get what it gives
them: with **+user:edit** every user there gets **edit**. It is of no
use for a normal ACL.  
This goes one level deep. For the units below those and what is in them,
add **-r**.

**-r**  
Set the ACL, as it is written, on everything below the site that knows
it: every unit and every object in them, all the way down. So **-r**
with **view** puts **view** on all of them.  
With **-a** it also hands a default ACL down all the way.

**--objects *type1,type2***  
Only touch objects of these types, for example **user,token**.

**--procs *num***  
A run with **-r** or **-a** walks every unit of the site and every
object in them. Where a unit holds many, its objects are shared out over
several processes, and this says how many. Without it a quarter of the
cores of the node, which leaves the rest for the daemons that go on
serving logins while this runs.

Needs the ACL **add:acl**.

**del_acl \[**-r**\] \[**-a**\] \[**--objects** *types*\] \[**--procs** *num*\] *site* *acl*\[,*acl*\]**  
Take those ACLs away again.  
Here an *acl* is the whole entry, owner and all, the way **list_acls**
prints it: **role:berlin/helpdesk:view**.  
Without an option only the entry on the site goes, and what was handed
down stays where it is.

**-a**  
Take back what a default ACL handed down: the units at the top of the
site lose it, and the objects in those units lose the ACL it gave them.
Removing **+user:edit** this way takes **edit** from every user there.  
OTPme does not keep where an ACL came from. If the same role or token
was given **edit** on one of those users by hand, that goes as well.

**-r**  
Remove the ACL, as it is written, from everything below the site that
has it; with **-a**, take back all the way down.

**--objects, **--procs****  
As with **add_acl**.

Needs the ACL **delete:acl**.

**list_acls *site***  
Show the ACLs that lie on this site, i.e. who may do what with it.  
Needs the ACL **view:acl**.

A site cannot inherit ACLs, so there is no **enable_acl_inheritance**
here.

## Extensions and LDAP Attributes

A site is also an LDAP entry, **ou=***site* under the realm, and an
extension is what gives it one: the object classes it is of, and the
attributes those classes allow. What **ldapd** serves and what
**show_ldif** prints comes from them.

A site has the extension **base**, which makes it an
**organizationalUnit** with **ou** and **description**. The class allows
more, an address or a phone number for example, and those can be set
here.

**add_extension *site* *extension***  
Add an extension to the site. One that is not for sites is refused, and
so is one the site already has.  
Needs the ACL **add:extension**.

**remove_extension *site* *extension***  
Take it away again, with the classes and attributes it brought.  
Needs the ACL **remove:extension**.

**add_attribute *site* *attribute***=**\[*value*\]**  
Set an LDAP attribute of the site.

Only an attribute one of its classes allows: there is no setting an
attribute OTPme knows nothing about. An attribute can hold more than one
value, so this adds one and leaves the others.

The ACL is per attribute, **add:attribute:***attribute*, and a plain
**add:attribute** covers all of them.

**modify_attribute *site* *attribute* *old_value* *new_value***  
Put *new_value* in the place of *old_value*, and leave the other values
of the attribute alone.  
The ACL is **edit:attribute:***attribute*.

**del_attribute *site* *attribute***=**\[*value*\]**  
Remove that value, or the whole attribute where no value is given.  
A mandatory attribute of a class the site is of cannot be removed, and
neither can a read-only one. The ACL is
**delete:attribute:***attribute*.

**add_object_class *site* *class***  
Add an LDAP object class to the site, beyond the ones its extensions
brought.  
Needs the ACL **add:object_class**.

**del_object_class *site* *class***  
Remove one again.  
Needs the ACL **delete:object_class**.

**show_ldif *site* \[**-a** *attribute1,attribute2*\]**  
The site as LDAP sees it. **-a** prints only those attributes.

## Export and Cleanup

**export \[**--password** *password*\] *site***  
Write the whole object of the site to stdout, as JSON.  
Without **--password** it is written as it is, in clear — **and that is
every key and every secret the site has**: the key of the site, the keys
of the portal and of RADIUS, the signing keys of OIDC, the secrets of
the portal and the cluster key. With one, a key is derived from that
password and the object is encrypted with it; the salt goes into the
output, so the password is all you need to read it back.  
Needs the ACL **export**.

**remove_orphans \[**-r**\] *site***  
Remove references to objects that are gone: orphan ACLs, policies and
signatures of the site, a trusted site that was deleted, and an SSO host
that was deleted.  
**-r** goes on through every unit of the site and the objects in them,
and cleans those up as well.  
It asks once for what it found on an object; the global option **-f**
skips the question.  
Needs the ACL **remove:orphans**.

# ADD OPTIONS

These options are used with the **add** command, next to **--trust**
which is described there.

## CA Certificate Options

These are kept in the CA of the new site and go into its certificate
when the master node joins.

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

There is no option for a key length or for how long a certificate is
valid. **add** makes no key, no certificate and no secret: the CA of the
site, the site itself and the master node get theirs when that node
joins, and the keys are made on it. So are the secrets of the site —
those of the SSO portal, of tiqr and the cluster key — and the site that
ran **add** never has them. The lengths are then the **--site-key-len**
(the key of the CA) and the **--host-key-len** (the key of the node) of
**otpme-tool join**, see **otpme-tool**(1). The key of the site and all
three validities are the defaults.

## Dictionary and ID Range Options

**--dicts *dict1,dict2***  
The word dictionaries the new site checks the strength of a password
against. They are added to the site and put into its
**password_strength** policy, in this order.  
Only the dictionaries OTPme comes with can be named: **english**,
**german**, **common-passwords**, **en-top10000**, **de-top10000**,
**english-guessing**, **german-guessing**, **us-male**, **us-female**,
**us-surnames**, **de-male**, **de-female**, **de-surnames**,
**at-surnames** and **abbreviations-it**. A name that is not one of them
is refused.  
Without this option the site gets none. More can be added later, see
**otpme-dictionary**(1).

**--no-dicts**  
Add no dictionary, whatever **--dicts** says.

**--id-ranges *range1,range2***  
The ranges the site takes the numbers of new users and groups from, each
written as *attribute***:***type***:***first***-***last*. They go into
the ID range policy of the site, see **otpme-policy**(1).  
Without this option the site gets
**uidNumber:s:70000-80000,gidNumber:s:70000-80000**. Every site gets
that same default, so give each site a range of its own: a user of one
site is known in all of them, with its number.

# OPTIONS

Every option belongs to one command and is described with that command
above.

Global options work with every command, see **otpme**(1).

# CONFIG PARAMETERS

A site is where the search for a config parameter ends, so it takes
nearly every one of them, and it has a value for each from the day it is
created. Which there are, and what each of them does, is in
**otpme**(7); **show_config** *site* prints the ones that are set.

One of them is for sites alone: **force_site_config_parameters** names
the parameters for which the value of the site wins over what an object
or a unit says.

# EXAMPLES

## A second site

On the master site:

**otpme-site add --trust berlin --id-ranges uidNumber:s:90000-100000,gidNumber:s:90000-100000 munich node1 login.munich.example.org 10.1.0.10**  
Create the site **munich** with its first node, and let it trust
**berlin**.

The site is disabled until that node has joined, which is done on the
node itself, see **otpme-tool**(1).

**otpme-site show**  
All sites, and whether the new one is enabled by now.

## An update of OTPme

Update OTPme on all nodes of the site first. Then, on a node or host of
the site:

**otpme-site maintenance berlin**  
The site is in maintenance, and this says why: the nodes run another
version than the site.

**otpme-site upgrade berlin**  
Store the objects in the format of the new version. When this is done,
maintenance ends.

## Logins that do not depend on the other site

On **berlin**:

**otpme-site add_trust berlin munich**  
The token secrets of berlin are synced to munich, so munich checks a
berlin user itself.

## A public certificate for the portal

**otpme-site sso_fqdn berlin login.example.org**  
The name users open. This makes a certificate of the site CA for it.

**otpme-site sso_cert --key privkey.pem berlin fullchain.pem**  
Put the public one in its place, with its key and the full chain.

Then, on every machine the portal runs on:

**otpme-controld reload httpd**  

## A new certificate for the site

**otpme-site renew_cert berlin**  

Then, on every node and every host of every site:

**otpme-tool sync --request-site-cert sites**  

## Keeping another site out

On **berlin**:

**otpme-site disable_auth munich**  
No user of munich is let in on berlin any more.

**otpme-site disable_sync munich**  
Berlin no longer syncs with munich.

## ACLs for all of a site

**otpme-site add_acl -r -a berlin role helpdesk "++user:edit"**  
The role may change every user of the site, the ones that are there and
the ones that come later.

**otpme-site add_acl berlin role auditors view**  
The role may look at the site object itself, and at nothing below it.

# FILES

*/etc/otpme/ssl/*realm***-***site***.pem***  
The certificate of a site, as each node and host keeps it. It is not
replaced by the sync, see **renew_cert**.

# SEE ALSO

**otpme**(1), **otpme**(7), **otpme-acls**(7), **otpme.conf**(5),
**otpme-realm**(1), **otpme-node**(1), **otpme-host**(1),
**otpme-ca**(1), **otpme-tool**(1), **otpme-client**(1),
**otpme-scope**(1), **otpme-policy**(1), **otpme-dictionary**(1),
**otpme-unit**(1), **otpme-pass**(1), **otpme-trash**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2026 the2nd. License: GPLv3
