# NAME

otpme-site - manage OTPme sites

# SYNOPSIS

**otpme-site** *command* \[*options*\] \[*site*\]

# DESCRIPTION

**otpme-site** manages sites in the OTPme system. A site contains nodes
and has its own CA hierarchy. Sites can establish trust relationships
with other sites to enable cross-site authentication and
synchronization.

# COMMANDS

## Site Management

**add \[*options*\] *site* *node_name* *site_fqdn* *site_address***  
Create a new site with a master node.  
**--trust *site1***,***site2*** names the sites the new site trusts, so
the trusts need not be added one by one afterwards (see **add_trust**).
A name that belongs to no site is refused before anything is created.

**del *site***  
Delete a site.

**show \[*site*\]**  
Display site information.

**list \[*regex*\]**  
List sites, optionally filtered by regex pattern.

**enable *site***  
Enable a disabled site.

**disable *site***  
Disable a site without deleting it.

**touch *site***  
Re-index the object to fix potential index problems.

## Site Configuration

**address *site* \[*ip_address*\]**  
Change site IP address.

**auth_fqdn *site* *fqdn***  
Change site auth FQDN.

**mgmt_fqdn *site* *fqdn***  
Change site management FQDN.

**config \[**-d**\] \[**-a**\] *site* *parameter* \[*value*\]**  
Set a configuration parameter. Use **-d** to delete (reset to default)
or **-a** to append the value to a list-typed parameter.

**upgrade *site***  
Add the configuration parameters the site is missing, with their
defaults. A site gets every parameter when it is created, so parameters
introduced by a later OTPme version are not set on an existing site
until this is run. Parameters that are already set are not changed.

**show_config *site* \[*parameter*\]**  
Show all configuration parameters.

**get_config *site* *parameter***  
Show the value of a single configuration parameter.

**description *site* \[*description*\]**  
Set site description.

**info \[**--language** *LANG*\] *site* \[*info*\]**  
Set free-form info text. If *info* is omitted, the current info text is
opened in the editor specified by the **EDITOR** environment variable.

**dump_info \[**--language** *LANG*\] *site***  
Dump the info text to stdout.

## Trust Relationships

**add_trust *site* *trusted_site***  
Add a trust relationship with another site.

**del_trust *site* *trusted_site***  
Delete a trust relationship.

## Authentication and Synchronization

**enable_auth *site***  
Enable authentication with site.

**disable_auth *site***  
Disable authentication with site.

**enable_sync *site***  
Enable synchronization with site.

**disable_sync *site***  
Disable synchronization with site.

## Certificate Management

**dump_cert *site***  
Dump site certificate to stdout.

**dump_key \[**-p** *passphrase*\] *site***  
Dump site private key to stdout. Use **-p** to encrypt with passphrase.

**dump_ca_chain *site***  
Dump site certificate chain to stdout.

**renew_cert *site***  
Renew site certificate.

**site_cert *site* \[*cert_file*\]**  
Change the site certificate. Without *cert_file* the certificate is read
from stdin.

## RADIUS Certificate

**radius_cert \[**--key** *radius_key*\] \[**--ca-cert** *radius_ca_cert*\] *site* \[*radius_cert*\]**  
Change the RADIUS certificate. The optional **--key** and **--ca-cert**
flags set the matching private key and CA certificate in one call.

**radius_key *site* *key_file***  
Change RADIUS certificate key.

**radius_ca_cert *site* \[*radius_ca_cert*\]**  
Change the RADIUS CA certificate used to verify the RADIUS certificate
above.

## SSO Configuration

**sso_fqdn *site* *fqdn***  
Change the site's SSO FQDN (see the OIDC OP section below).

**sso_cert \[**--key** *sso_key*\] *site* \[*cert_file*\]**  
Change the SSO certificate. Use **--key** to set the matching private
key in the same call.  
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

**sso_key *site* *key_file***  
Change SSO certificate key.

**sso_secret *site* *secret***  
Change SSO secret.

**sso_csrf_secret *site* *secret***  
Change SSO CSRF secret.

**add_sso_host *site* *host_name***  
Mark a host as SSO host. An SSO host is a host that can provide the SSO
portal. The following SSO related data will be synchronized to this
host:

SSO_SECRET  
Flask session secret used by the SSO portal to sign session cookies.

SSO_CSRF_SECRET  
Secret used by the SSO portal for CSRF token protection.

SSO_CERT  
TLS certificate presented by the SSO portal (**httpd**).

SSO_KEY  
Private key matching the SSO TLS certificate.

OIDC_PAIRWISE_SECRET  
HMAC key used to derive pairwise OIDC *sub* claims. Replicated to all
SSO hosts of a site so every host computes the same *sub* for the same
(RP, user) pair.

To actually start the SSO portal on the host, set **SSO_SERVER="True"**
in */etc/otpme/otpme.conf*. See **otpme.conf**(5).

**remove_sso_host *site* *host_name***  
Remove the SSO host role from a host. The SSO data will no longer be
synchronized to this host. The host itself stays as it is. Takes a UUID
as well, so a host that was deleted while it was an SSO host can still
be taken off the site. Needs the ACL **remove:sso_host**.

**sso_logo *site* *image_path***  
Set the logo the SSO portal of this site shows on its login and recovery
pages. PNG or JPEG, at most 512 KiB — it is part of the site object,
which every node and host of the realm synchronizes. A site without a
logo shows the OTPme logo the portal ships with. The tiqr app shows the
same logo for the accounts enrolled here.

**dump_sso_logo *site***  
Dump the site's SSO portal logo as base64 to stdout.

**del_sso_logo *site***  
Remove the site's SSO portal logo, so the portal shows the default one
again.

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
intentionally not supported -- OAuth 2.1 §1.4 deprecates it because
tokens delivered via the URL fragment leak through browser history,
referrers, XSS and extensions; modern SPAs should use Code+PKCE instead.
The **Hybrid Flow** (response_type="code id_token") is likewise not
supported; its only marginal benefit (immediate identity rendering
before the /token call) does not justify the additional fragment-based
delivery surface. PKCE is mandatory by default
(**oidc_pkce_required=True**) and only **S256** is advertised in
discovery; **plain** can be enabled per client for legacy interop but is
never advertised (see **oidc_allow_plain_pkce**).

**enable_oidc *site***  
Enable the OIDC OP on this site. On first activation, an active signing
key (**renew_oidc_key**) and a pairwise secret are auto-generated.

**disable_oidc *site***  
Disable the OIDC OP. Existing keys and secrets are kept on disk so
**enable_oidc** resumes without re-issuing tokens.

**renew_oidc_key \[**--key-type** *preset*\] \[**--kty** *RSA\|EC\|OKP*\] \[**--size** *N*\] \[**--alg** *alg*\] *site***  
Rotate the active OIDC signing key. The previous active key is demoted
to **retired** and removed from JWKS once the site's
**oidc_retired_max_age** config parameter (default 7200s) has elapsed,
so RPs that fetched ID Tokens just before rotation can still verify
them. Presets: **rsa**, **rsa-3072**, **rsa-4096**, **ec**, **ec-p256**,
**ec-p384**, **ec-p521**, **ed25519**. Direct configuration: **--kty**
(**RSA**/**EC**/**OKP**), **--size** (RSA bits or EC/OKP curve),
**--alg**
(**RS256**/**RS384**/**RS512**/**ES256**/**ES384**/**ES512**/**EdDSA**).

**revoke_oidc_key *site* *kid***  
Permanently remove a signing key from JWKS. Tokens signed by it stop
verifying immediately. If the revoked key was the active one, a
replacement is generated automatically.

**show_oidc_keys *site***  
List the OIDC signing keys currently on the site (active, retired, and
their algorithms / kid).

**oidc_pairwise_secret *site* \[*secret*\]**  
Rotate (or set) the pairwise sub HMAC secret for this site. Without
*secret* a fresh 64-hex-char key is auto-generated. Asks for
confirmation; use the global **-f** to skip it. **WARNING:** rotating
invalidates every existing pairwise *sub* on every RP -- RPs that key
their account model on *sub* will see a "fresh" user on next login.
Coordinate with each RP before rotating.

**tiqr_secret *site* \[*secret*\]**  
Rotate (or set) the tiqr HMAC secret for this site. Without *secret* a
fresh 64-byte key is auto-generated. The secret derives the challenge
and the poll id of a tiqr login attempt, both of which live for
**tiqr_challenge_expiry** seconds, so rotating only breaks logins that
are in progress at that moment. Enrolled phones, token secrets and
existing sessions are unaffected.

Site / Unit / Client config parameters relevant to OIDC:

> oidc_pkce_required  
> Whether PKCE is mandatory for the authorize flow. Default **True**
> (OAuth 2.1).
>
> oidc_allow_plain_pkce  
> Whether the deprecated **plain** PKCE method is accepted. Default
> **False**. Override per client only for legacy RPs that hardcode
> **plain**; the discovery document never advertises it regardless.
>
> oidc_logout_scope  
> Scope of */end_session*: **sso** (default) terminates the whole SSO
> session via the regular logout cascade; **rp** terminates only the
> OIDCSession for this RP.
>
> oidc_require_consent  
> Whether the OP renders an end-user consent screen at */authorize*.
> Default **False** -- enterprise-SSO assumes admin-side Scope
> allowlists are the policy boundary. Set **True** per client for
> public-facing / multi-tenant RPs. Granted consents are remembered per
> (user, client) trust-on-first-use; a wider scope request re-prompts.
> The OIDC **prompt=consent** request parameter forces the screen even
> when a stored consent exists. End users review and revoke their
> consents in the SSO portal Settings page.
>
> oidc_default_scopes  
> Comma-separated list of scopes auto-granted to RPs without an explicit
> Scope-object grant.
>
> oidc_email_attribute  
> LDIF attribute used as the source for the *email* claim.

## Cluster

**cluster_key *site* *cluster_key***  
Change cluster key.

## FIDO2 CA Certificates

**add_fido2_ca_cert *site* *ca_cert_file***  
Add a FIDO2 CA certificate.

**del_fido2_ca_cert *site* *subject***  
Delete a FIDO2 CA certificate by subject.

**list_fido2_ca_certs *site***  
List FIDO2 CA certificates.

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

**add_acl \[**-r**\] \[**-a**\] \[**--objects** *types*\] \[**--procs** *num*\] *site* *owner_type* *owner* *acl***  
Add an access control entry. Use **-r** for recursive, **-a** to apply
default ACLs to existing objects.

A recursive run walks every unit of the site and every object in them.
Where a unit holds many, its objects are shared out over several
processes. **--procs** says how many. Without it a quarter of the cores
of the node, which leaves the rest for the daemons that go on serving
logins while this runs.

**del_acl \[**-r**\] \[**-a**\] \[**--objects** *types*\] \[**--procs** *num*\] *site* *acl***  
Remove an access control entry. **--procs** as above.

**list_acls *site***  
Display all ACLs for the site.

## Extension and Attribute Management

**add_extension *site* *extension***  
Add an extension to the site.

**remove_extension *site* *extension***  
Remove an extension from the site.

**add_attribute *site* *attribute*=*value***  
Add an LDAP attribute to the site.

**modify_attribute *site* *attribute* *old_value* *new_value***  
Modify an LDAP attribute of the site.

**del_attribute *site* *attribute*=*value***  
Remove an LDAP attribute from the site.

**add_object_class *site* *class***  
Add an LDAP object class to the site.

**del_object_class *site* *class***  
Remove an LDAP object class from the site.

**show_ldif \[**-a** *attributes*\] *site***  
Show LDIF representation of the site. Use **-a** to show only specific
attributes.

## Import/Export

**export \[**--password** *PASS*\] *site***  
Export site configuration.

**remove_orphans \[**-r**\] *site***  
Remove orphaned object references. Use **-r** for recursive.

# ADD OPTIONS

These options are used with the **add** command:

## CA Certificate Options

**--ca-valid *DAYS***  
CA certificate validity in days.

**--ca-key-len *BITS***  
Key length for CA certificates in bits.

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

## Site and Node Certificate Options

**--site-valid *DAYS***  
Site certificate validity in days.

**--site-key-len *BITS***  
Key length for site certificate in bits.

**--node-valid *DAYS***  
Master node certificate validity in days.

**--node-key-len *BITS***  
Key length for master node certificate in bits.

## Dictionary and ID Range Options

**--no-dicts**  
Do not add any word dictionaries for password strength checking.

**--dicts *dict1,dict2***  
Add the given word dictionaries for password strength checking.

**--id-ranges *range1,range2***  
ID ranges to add.

# OPTIONS

## Display Options

**-a**  
Show all sites.

**-z *SIZE***  
Limit output size.

**--fields *FIELD1,FIELD2***  
Display only specified fields.

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
Display specific attribute in list command.

## General Options

**--password *PASS***  
Password for encrypting exports.

**--objects *type1,type2***  
Limit ACL operations to specific object types.

Global options are available for all commands. See **otpme**(1) for
details.

# CONFIG PARAMETERS

Configuration parameters can be set with the **config** command and
displayed with **show_config**. For a complete description of all
available parameters and their applicable object types, see
**otpme**(7).

# EXAMPLES

**otpme-site add mysite node1 site.example.com 10.0.0.1**  
Create a new site

**otpme-site add_trust mysite othersite**  
Add trust relationship

**otpme-site dump_cert mysite**  
Dump site certificate

# FILES

*/var/lib/otpme/*  
OTPme data directory

# SEE ALSO

**otpme**(1), **otpme**(7), **otpme-acls**(7), **otpme-realm**(1),
**otpme-node**(1), **otpme-ca**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
