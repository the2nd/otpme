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

**config \[**-d**\] *site* *parameter* \[*value*\]**  
Set a configuration parameter. Use **-d** to delete (reset to default).

**show_config *site* \[*parameter*\]**  
Show all configuration parameters.

**description *site* \[*description*\]**  
Set site description.

**info *site* \[*info*\]**  
Set free-form info text. If *info* is omitted, the current info text is
opened in the editor specified by the **EDITOR** environment variable.

**dump_info *site***  
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

**revoke_cert *site***  
Revoke site certificate.

**renew_cert *site***  
Renew site certificate.

## RADIUS Certificate

**radius_cert *site* *cert_file***  
Change RADIUS certificate.

**radius_key *site* *key_file***  
Change RADIUS certificate key.

**del_radius_cert *site***  
Delete RADIUS certificate.

**del_radius_key *site***  
Delete RADIUS key.

## SSO Configuration

**sso_cert *site* *cert_file***  
Change SSO certificate.

**sso_key *site* *key_file***  
Change SSO certificate key.

**del_sso_cert *site***  
Delete SSO certificate.

**del_sso_key *site***  
Delete SSO key.

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

**del_sso_host *site* *host_name***  
Remove the SSO host role from a host. The SSO data will no longer be
synchronized to this host.

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
key (**gen_oidc_key**) and a pairwise secret are auto-generated.

**disable_oidc *site***  
Disable the OIDC OP. Existing keys and secrets are kept on disk so
**enable_oidc** resumes without re-issuing tokens.

**gen_oidc_key \[**--key-type** *preset*\] \[**--kty** *RSA\|EC\|OKP*\] \[**--size** *N*\] \[**--alg** *alg*\] \[**--retired-max-age** *seconds*\] *site***  
Rotate the active OIDC signing key. The previous active key is demoted
to **retired** and removed from JWKS once *retired_max_age* (default
7200s) has elapsed, so RPs that fetched ID Tokens just before rotation
can still verify them. Presets: **rsa-2048**, **rsa-3072**,
**rsa-4096**, **ec-p256**, **ec-p384**, **ec-p521**, **ed25519**.

**revoke_oidc_key *site* *kid***  
Permanently remove a signing key from JWKS. Tokens signed by it stop
verifying immediately. If the revoked key was the active one, a
replacement is generated automatically.

**show_oidc_keys *site***  
List the OIDC signing keys currently on the site (active, retired, and
their algorithms / kid).

**oidc_pairwise_secret \[**--force**\] *site* \[*secret*\]**  
Rotate (or set) the pairwise sub HMAC secret for this site. Without
*secret* a fresh 64-hex-char key is auto-generated. **WARNING:**
rotating invalidates every existing pairwise *sub* on every RP -- RPs
that key their account model on *sub* will see a "fresh" user on next
login. Coordinate with each RP before rotating.

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

## Policy Management

**add_policy *site* *policy***  
Attach a policy to the site.

**remove_policy *site* *policy***  
Remove a policy from the site.

**list_policies *site***  
List policies attached to the site.

## ACL Management

**add_acl \[**-r**\] \[**-a**\] \[**--objects** *types*\] *site* *owner_type* *owner* *acl***  
Add an access control entry. Use **-r** for recursive, **-a** to apply
default ACLs to existing objects.

**del_acl \[**-r**\] \[**-a**\] \[**--objects** *types*\] *site* *acl***  
Remove an access control entry.

**show_acls *site***  
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

**otpme**(1), **otpme**(7), **otpme-realm**(1), **otpme-node**(1),
**otpme-ca**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
