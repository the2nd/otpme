# NAME

otpme - OTPme authentication and authorization system architecture

# DESCRIPTION

**OTPme** is a comprehensive authentication and authorization system
that provides secure multi-factor authentication, granular access
control, and centralized identity management. This manual page describes
the overall architecture, core concepts, and design principles of OTPme.

A central design principle of OTPme is that each user can have
**multiple authentication tokens** assigned simultaneously. Different
tokens can be used for different services, allowing fine-grained control
over how a user authenticates to each resource.

For example, consider WLAN authentication: instead of sharing a single
password across all of a user's devices, an administrator can assign a
separate password token for each device (laptop, phone, tablet). If a
device is stolen, the administrator simply deletes that device's token.
All other devices continue to work without any reconfiguration - there
is no need to change the WLAN password on every remaining device.

This per-service token design also provides strong security isolation.
Since each token only grants access to the service it is assigned to,
someone who obtains a user's WLAN password cannot use it to access the
user's email, file shares, or system login. Each service is protected by
its own independent credentials.

A user might log in to their workstation with a FIDO2 hardware key,
access file shares with the same FIDO2 token, authenticate to WLAN with
per-device passwords via RADIUS, and use a dedicated password token for
groupware access (CalDAV, CardDAV, IMAP) from a smartphone where
credentials are stored persistently on the device - all managed
centrally under one identity.

Access control is enforced through **clients** and **access groups.**
Each service that authenticates against OTPme is represented as a client
object. An access group is assigned to each client, and only tokens or
roles that are members of that access group are permitted to
authenticate.

A client can be a **RADIUS client,** where the RADIUS NAS identifier
must match the OTPme client name. For example, a WLAN access point
configured with NAS ID "wlan-office" must have a corresponding OTPme
client named "wlan-office". Only tokens assigned to that client's access
group will be accepted for WLAN authentication.

Alternatively, a client can be an **LDAP client,** authenticating
against **otpme-ldapd**. In this case the client name is specified as a
DC component in the LDAP bind DN. For example, a bind DN of
*uid=user1,ou=users,dc=mailserver,dc=example,dc=com* maps to the OTPme
client "mailserver". This way, the mail server can only authenticate
users who hold tokens assigned to the mail server's access group.

# ARCHITECTURE OVERVIEW

OTPme is built on a distributed, hierarchical architecture with the
following key components:

## Daemons

**controld**  
Main daemon controller. Starts, stops, and monitors all other OTPme
daemons.

**mgmtd**  
Management daemon. Handles all administrative operations such as
creating, modifying, and deleting objects (users, tokens, policies,
etc.).

**authd**  
Authentication daemon. Handles authentication requests, validates
credentials, and manages sessions.

**syncd**  
Synchronization server daemon. Serves objects from all sites to hostd
instances. On nodes, objects from other sites are synchronized between
hostd and syncd. Objects from the local site are synchronized between
nodes by the clusterd.

**hostd**  
Host daemon. Runs on both hosts and nodes. Acts as a sync client that
pulls object updates from a node's syncd. On hosts, hostd synchronizes
objects from all sites with the syncd on nodes.

**clusterd**  
Cluster daemon. Manages cluster coordination, quorum, and master
failover between nodes within a site. Also handles synchronization of
local site objects between nodes.

**joind**  
Join daemon. Handles the process of joining a host or node to an OTPme
site.

**ldapd**  
LDAP daemon. Provides an LDAP interface so that external services can
authenticate users and query directory data against OTPme.

**httpd**  
HTTP daemon. Serves the web SSO interface.

**fsd**  
File server daemon. Handles file share access for FUSE-mounted OTPme
shares.

**scriptd**  
Script daemon. Executes server-side scripts (e.g. authentication
scripts, push scripts).

## External Integrations

**FreeRADIUS**  
OTPme integrates with FreeRADIUS to provide RADIUS authentication (e.g.
WLAN, VPN). OTPme includes a FreeRADIUS module (rlm_python) that
forwards RADIUS requests to the authd. Alternatively, FreeRADIUS can use
the **otpme-auth** command, which serves as a replacement for ntlm_auth.
Any application that supports RADIUS (e.g. via pam_radius_auth) can
authenticate against OTPme.

**PAM Module**  
OTPme includes a Python PAM module that enables authentication with
token types such as FIDO2 or YubiKey HMAC challenge-response during
system login. Upon login, the **otpme-agent** is started to manage a
realm session and connections to the mgmtd. Through the otpme-agent,
users can manage OTPme objects (users, groups, tokens, etc.) and access
file shares served by the fsd without re-authenticating.

**NSS (libnss-cache)**  
OTPme uses libnss-cache to make OTPme users and groups available as
local Linux accounts. The cache files are generated by the hostd using
nsscache.

# ORGANIZATIONAL STRUCTURE

OTPme organizes infrastructure in a three-level hierarchy:

## Realms

A **realm** is the top-level administrative domain, comparable to a
Windows domain. It represents a completely independent authentication
domain with its own users, groups, policies, roles, units, and other
objects. Realms are currently completely independent and cannot be
connected to each other.

A realm contains one or more sites. Users and groups are realm-wide,
meaning they exist across all sites. Other objects such as units, roles,
and policies are per-site. The only user that exists per-site is the
root user.

## Sites

A **site** is a separate administrative area within a realm. Typically,
a site is created for each physical location. Since the nodes of a site
form a cluster, this provides redundancy per location. Each site has its
own root user who can manage the site's users, groups, and other
objects. Additionally, each site has a **site_admin** role that can be
assigned to a "user/token" to grant administrative rights for that site.
Normal users can be granted specific modify rights on objects via ACLs,
including across sites.

By default, token secrets are not synchronized to other sites. When a
user from site1 tries to log in on a host belonging to site2, the
authentication request is forwarded to site1. To allow local
authentication without forwarding, site1 must be configured to trust
site2 (site trust). With trust enabled, token secrets are replicated to
the trusted site, allowing direct local authentication.

Depending on the use case, users can either be created per-site or
centrally in the master site with a site trust configured. Creating
users per-site allows independent administration at each location, while
creating all users in the master site with trust provides centralized
administration.

Nodes and hosts are created per-site but must have realm-wide unique
names. The nodes of each site form a cluster.

## Units

**Units** are comparable to LDAP OUs and are used to store objects.
Policies and ACLs can be assigned to a unit - for example, ACLs to allow
a token or role to create, delete, or edit objects within the unit, or
policies that determine which groups and roles a "user/token" belongs
to.

# CORE OBJECT TYPES

## Users

User accounts represent identities that can authenticate to the system.
Each user has a unique user ID (username) and gets assigned a unique UID
(Unix user ID).

Every user has a default token (login) for authenticating to the realm.
Additional tokens can be added for specific services - for example,
separate password tokens for WLAN access on a notebook and smartphone.

Each user has a default group. The group is not added to the user -
instead, the user is added to the group as a "default group user". This
prevents an administrator of site1 from assigning a group from site2 to
a user on site1.

Policies and ACLs can also be assigned to a user - for example, ACLs
that allow another "user/token" to edit the user, or a policy that
determines in which unit objects (e.g. groups) are created by default.

Extensions can be added to a user. By default, the extensions "base" and
"posix" are assigned. Both are LDAP extensions that define which LDAP
attributes are available for the user.

## Tokens

Tokens are authentication credentials assigned to users. OTPme supports
diverse token types:

-   **TOTP/HOTP** - RFC 6238/4226 one-time passwords

-   **FIDO2** - Hardware security keys and platform authenticators

-   **U2F** - Universal 2nd Factor security keys

-   **SSH** - Public key authentication

-   **Password** - Static passwords with policy enforcement

-   **YubiKey** - HMAC-SHA1 challenge-response

-   **YubiKey PIV** - PIV smart card authentication using a YubiKey. The
    private key stays on the YubiKey and is used for challenge-response
    authentication. Can also be used for SSH key management and file
    encryption/decryption.

-   **Link** - Reference to another user's token

-   **Script** - Custom authentication via external scripts

A key concept in OTPme is that tokens - not users - are added to groups
and roles. Typically, it is the user's default token (login) that is
assigned to groups and roles.

Tokens support offline authentication, allowing secure access when the
OTPme server is unreachable.

## Groups

A group in OTPme is automatically a Linux group on hosts and nodes, so
it can be used to assign filesystem permissions. To add a user to a
group, the user's default token is added to the group. Alternatively,
the default token can be added to a role, and the role is then added to
the group.

There is a built-in group "realmusers" that automatically contains all
users of the realm. Additionally, each site has a group named after the
site (e.g. "berlin") that automatically contains all users of that site.

Groups can also be used as sync groups to control which users are
synchronized to a host.

## Roles

A role is essentially a group of tokens. In almost all places where a
token can be assigned, a role can be used instead. This extends and
simplifies permission management. Roles can also be added to other
roles, enabling hierarchical permission structures.

There are built-in default roles: **REALM_USER** and **SITE_ADMIN.** By
default, every user's default token is added to the REALM_USER role.
This allows the user to log in to the realm and automatically makes them
a member of the "realmusers" group. Adding a "user/token" to the
SITE_ADMIN role grants site administrator privileges.

A good example of how roles work: a role "groupware" grants access to
the groupware (CalDAV, CardDAV, IMAP), and a role "employee" is added to
the role "groupware". Every employee automatically gets groupware
access. A role "marketing" can then be added to the role "employee" and
also to the group "marketing". Adding a marketing user's default token
to the role "marketing" gives them both groupware access and membership
in the marketing group. If all employees should later get access to an
additional service (e.g. a wiki), only the role "employee" needs to be
added to the corresponding access group (see Access Groups) and the
permission is granted for all employees.

## Access Groups

Access groups are used to control access to services and to define
session parameters. A client (RADIUS, LDAP) is assigned an access
group - for example, the access point "ap01" gets the access group
"wlan". Tokens or roles are then assigned to the access group to grant
access to the service. When a WLAN authentication request arrives, the
access group determines who is allowed access.

Additional parameters can be configured per access group, such as how
many failed authentication attempts lock a user out of the access group
and for how long (e.g. 5 minutes).

Each access group can be configured to create a session for requests.
This is useful when a service sends recurring requests with the same
password or OTP (e.g. an IMAP server). Note that an OTP login is then no
longer one-time but remains valid for the duration of the session. Per
access group, the session lifetime and the maximum number of parallel
sessions can be configured.

Access groups can have child access groups. For example, the default
access group "SSO" (the OTPme SSO portal) can have "nextcloud" as a
child access group. Tokens and roles that have access to the SSO access
group then automatically get access to the nextcloud access group as
well.

## File Shares

OTPme file shares require a shared storage backend mounted on all nodes
(e.g. under /otpme-mounts/ or /otpme-mounts/share1). The mount point is
assigned to the share as its root_dir. It is important that this backend
is made available on all nodes equally. CephFS or NFS is recommended as
backend.

Tokens or roles are assigned to a share to grant access. Clients mount
shares via FUSE using **otpme-mount**. By default, all nodes serve a
share. Specific nodes can be assigned to a share, in which case only
those nodes will serve it. The client/host mounts the share from a
random node (load balancing).

A share can optionally be created as an encrypted share. During
creation, a master password is requested from which the AES key is
derived. Since encryption happens on the client/host side, an encrypted
copy of the AES key must be added for each token that should access the
encrypted share. This is also the reason why only tokens - not roles -
can be assigned to an encrypted share.

## Node Pools

A node pool is a collection of nodes. A node pool can be assigned to a
share, and then the share is only served by the nodes in that pool.

## Policies

Policies implement business rules and security controls. They can be
attached to various objects such as units, users, tokens, or access
groups.

**authonaction**  
Requires re-authentication when performing sensitive actions (e.g.
modify, delete, add ACL). Configurable timeout and expiry. Tokens and
roles can be whitelisted.

**autodisable**  
Automatically disables objects after a specified time (e.g. +1h, +1D,
+1W, +1M, +1Y). Can optionally count from last usage instead of
assignment time.

**defaultgroups**  
Automatically assigns new users to preconfigured groups upon creation.
Can also set the default group of a user.

**defaultpolicies**  
Automatically attaches preconfigured policies to new objects of a given
type.

**defaultroles**  
Automatically assigns preconfigured roles to the default token of new
users.

**defaultunits**  
Specifies default units for different object types, controlling where
new objects are placed.

**forcetoken**  
Restricts which token types and authentication methods can be used for
authorization.

**idrange**  
Defines ID ranges for automatic assignment of the LDAP attributes
uidNumber and gidNumber. Supports sequential and random allocation.

**logintimes**  
Restricts login to specific times using a cron-like format (e.g. work
hours only, weekdays only).

**objecttemplates**  
Automatically applies template objects (preconfigured settings) to new
users or hosts.

**password**  
Enforces password and PIN strength requirements (minimum length,
character complexity, dictionary-based strength checking).

**tokenacls**  
Automatically assigns ACLs to new tokens, controlling what users and
creators can do with them.

# ACCESS CONTROL

OTPme implements a sophisticated multi-layer access control system:

## ACLs (Access Control Lists)

Fine-grained permissions controlling who can perform what operations on
which objects. ACLs are assigned to a "user/token" or a role. ACLs
support:

-   Object-specific permissions (view, modify, delete, enable, disable)

-   Sub-type permissions - e.g. "enable:object" grants enabling the
    object itself, while "enable" without a sub-type grants all enable
    permissions (enable:object, enable:mschap, etc.)

-   Inheritance from parent objects (e.g. ACLs on a unit apply to all
    objects within)

# OFFLINE AUTHENTICATION

When the OTPme server is unreachable, hosts can authenticate users
against locally cached offline data. Offline authentication must be
explicitly enabled per token.

During an online login, the token configuration and session data are
encrypted and cached locally on the host. The offline data is encrypted
using Argon2i key derivation based on the user's password, PIN, or
smartcard response.

When the server is unreachable, credentials are verified against the
local cache. Already used OTPs are tracked locally to prevent replay
attacks. Configurable expiration times control how long the offline
cache remains valid (by login age and by inactivity).

When the server becomes available again, the hostd synchronizes used
OTPs and token counters back to the server.

# CONFIG PARAMETERS

Configuration parameters are set per-object using the **config** command
and displayed with **show_config**. Parameters set on a parent object
(e.g. site or unit) act as defaults for all child objects unless
overridden locally. The column *Object types* lists on which object
types each parameter can be set.

**otpme-site config mysite parameter \[*value*\]**  
**otpme-site config -d mysite parameter \[*value*\]**

## General

**confirmation_policy (str, default: paranoid)**  
Controls when OTPme asks for user confirmation. Valid values:
**paranoid** (ask for confirmation on all changes; deleting requires
typing the object name), **normal** (only ask when deleting objects;
requires typing the object name to confirm), **force** (never ask for
confirmation). The **-f** command line option also skips all
confirmations regardless of the policy.  
Object types: site, unit, token

**auto_sign (bool, default: false)**  
If enabled, the user is offered to sign the object after each change.  
Object types: site, unit, user, token

**auto_revoke (bool, default: true)**  
If enabled, object signatures are automatically revoked when the object
is changed.  
Object types: site, unit, token, script

## Key Backup

**private_key_backup_key (str)**  
Public RSA key (base64-encoded) used for encryption of user private key
backups. If not set, a new key pair is generated automatically.  
Object types: site, unit

**private_key_backup_key_len (int, default: 2048)**  
RSA key length for the private key backup key. Valid values: 2048,
4096.  
Object types: site, unit

## Password Hashing

**default_pw_hash_type (str, default: Argon2_i)**  
Default hash algorithm for new password tokens. Available types depend
on registered hash modules (e.g. Argon2_i, Argon2_d, PBKDF2, HKDF).  
Object types: site, unit, user, token

**session_hash_type (str, default: Argon2_i)**  
Hash algorithm used for session passwords.  
Object types: site, unit, user, token

## User Scripts

**default_key_script (str)**  
Path of the default key script added to new users.  
Object types: site, unit

**default_auth_script (str)**  
Path of the default auth script added to new users.  
Object types: site, unit

**default_agent_script (str)**  
Path of the default agent script added to new users.  
Object types: site, unit

**default_login_script (str)**  
Path of the default login script added to new users.  
Object types: site, unit

## User Management

**failed_pass_history (int, default: 16)**  
Number of failed login passwords to remember. Multiple failed login
attempts with the same wrong password do not count as separate failures
and will not lock the account.  
Object types: site, unit, user

**add_default_token (bool, default: true)**  
If enabled, a default token is automatically created for new users.  
Object types: site, unit

**default_token_name (str, default: login)**  
Name of the default token created for new users.  
Object types: site, unit

**default_token_type (str, default: hotp)**  
Token type of the default token created for new users.  
Object types: site, unit

**user_key_len (int, default: 2048)**  
RSA key length for user keys. Valid values: 2048, 4096.  
Object types: realm, site, unit, user

**allow_default_token_rename (bool, default: false)**  
If enabled, users are allowed to rename their default token.  
Object types: site, unit, user

**allow_default_token_deletion (bool, default: false)**  
If enabled, users are allowed to delete their default token.  
Object types: site, unit, user

**allow_temp_passwords (bool, default: false)**  
If enabled, temporary passwords can be set on tokens.  
Object types: site, unit, user, token

**sso_temp_pass_role (str)**  
Role whose members are allowed to set a temporary password on another
user's token through the SSO portal admin-access flow. Resolved per-user
with the standard cascade (token overrides user overrides unit overrides
site). Foreign-site users only resolve via this cascade if the local
site lists the home site under **sso_temp_pass_role_trusts**; otherwise
the local site's setting (site-only, no user/unit walk) is used as a
fallback.  
Object types: site, unit, user, token

**sso_temp_pass_role_trusts (list)**  
Comma-separated list of remote sites whose user-scoped
**sso_temp_pass_role** cascade this site trusts when a foreign user
opens an SSO portal admin-access session here. Sites not in the list
fall back to the local site's **sso_temp_pass_role**. Own-site users are
always trusted.  
Object types: site

**password_allowed_chars (str, default: 0-9A-Za-z!@#$%&\*()\_+-={}\[\]:;\<\>.?/)**  
Character set allowed in passwords (used by the password policy).  
Object types: site, unit, user

## Certificates

**cert_key_len (int, default: 2048)**  
RSA key length for CA-issued certificates. Valid values: 2048, 4096.  
Object types: site, unit, ca

**cert_sign_algo (str, default: sha256)**  
Signature algorithm for certificates. Valid values: sha256, sha512.  
Object types: site, unit, ca

**crl_sign_algo (str, default: sha256)**  
Signature algorithm for certificate revocation lists. Valid values:
sha256, sha512.  
Object types: site, unit, ca

## File Shares

**default_share_add_script (str)**  
Path of the default script used when adding new shares.  
Object types: site, unit

**default_share_mount_script (str)**  
Path of the default script used to mount shares.  
Object types: site, unit

**share_root (str, default: /otpme-mounts/)**  
Root directory for new shares. A new share automatically gets
*share_root*/*sharename* as its root directory (e.g. with
**share_root=/otpme-mounts/** a share named **projects** gets
**/otpme-mounts/projects** as its root directory).  
Object types: site, unit, user, token

## Hosts

**hosts_accessgroup (str)**  
Access group that new hosts are automatically added to when they are
created. This is useful for MAC Authentication Bypass (MAB) port
authentication, where hosts need to be assigned to an access group upon
registration. The value must be the name of an existing access group.  
Object types: site, unit

## Devices

**devices_accessgroup (str)**  
Access group that new devices are automatically added to when they are
created. This is useful for MAC Authentication Bypass (MAB) of network
devices such as IP phones or printers. The value must be the name of an
existing access group.  
Object types: site, unit

## VLAN

**vlan (str)**  
VLAN identifier to assign. This is used for VLAN assignment during
802.1x or MAB port authentication. The parameter can be set at various
levels; the most specific match wins (e.g. a VLAN set on a token
overrides the one set on the user or site).  
Object types: site, unit, host, device, user, token

## SSO Portal

**device_token_roles (list)**  
Comma separated list of roles to which device tokens registered via the
SSO portal are added. The role's info text is displayed in the SSO
portal settings to inform users about the purpose and scope of the role.
Each value can be a plain role name (resolved within the current site)
or a *site/role* path to reference a role on another site. The parameter
is resolved per user; the most specific match wins (user overrides unit
overrides site). Foreign-site users only resolve via this cascade if the
local site lists the home site under **device_token_roles_trusts**;
otherwise the local site's setting is used as a fallback.  
Object types: site, unit, user

**device_token_roles_trusts (list)**  
Comma-separated list of remote sites whose user-scoped
**device_token_roles** cascade this site trusts when a foreign user
registers a device token through the SSO portal here. Sites not in the
list fall back to the local site's **device_token_roles**. Own-site
users are always trusted.  
Object types: site

**device_token_suffix (str)**  
Suffix appended to the device token name when the SSO portal registers a
token under this role. A role without **device_token_suffix** is not
shown in the SSO portal at all, so this parameter doubles as the opt-in
switch that makes a role eligible as an SSO device-token target via
**device_token_roles**.  
Object types: role

**sso_allow_passkeys (bool, default: true)**  
Whether passkeys (FIDO2 resident credentials) are accepted as a login
method on this site. Set to false to refuse passkey authentication
entirely; the SSO portal login mask is unchanged. Foreign-site users
only resolve via this cascade if the local site lists the home site
under **sso_allow_passkeys_trusts**; otherwise the local site's setting
is used as a fallback.  
Object types: site, unit, user, token

**sso_allow_passkeys_trusts (list)**  
Comma-separated list of remote sites whose user-scoped
**sso_allow_passkeys** cascade this site trusts when a foreign user
opens the SSO portal here. Sites not in the list fall back to the local
site's **sso_allow_passkeys**. Own-site users are always trusted.  
Object types: site

**sso_allow_fido2_deploy (bool, default: true)**  
Whether end users may register a new FIDO2 token through the SSO portal
Settings page. Set to false to restrict FIDO2 deployment to
administrator workflows.  
Object types: site, unit, user, token

**sso_allow_totp_deploy (bool, default: true)**  
Whether end users may register a new TOTP token through the SSO portal
Settings page. Set to false to restrict TOTP deployment to administrator
workflows.  
Object types: site, unit, user, token

**sso_rate_limit_login (str, default: 100/minute)**  
Per-IP rate limit on the SSO portal /login POST endpoint. Coarse DoS
guard against high-volume attacks from a single source; deliberately
generous so NAT pools do not trip it under normal load. Accepts the
standard Flask-Limiter syntax (e.g. **100/minute**, **1000/hour**).  
Object types: site

**sso_rate_limit_login_user (str, default: 10/minute)**  
Per-username rate limit on the SSO portal /login POST endpoint. Targets
account brute-force regardless of source IP; works alongside authd's
auto_disable policy. NAT-safe because the key is the submitted
username.  
Object types: site

**httpd_ssl_socket_uri (str, default: tcp://\[::\]:443)**  
Listen socket URI for the SSO portal HTTPS (TLS) daemon. Supports
**tcp://address:port**. The most specific match wins (node/host override
unit overrides site) so individual SSO hosts can bind a non-default port
(e.g. when fronted by a reverse proxy).  
Object types: site, unit, node, host

**httpd_socket_uri (str, default: tcp://\[::\]:80)**  
Listen socket URI for the plain-HTTP CA-publish listener that serves the
Realm and Site CA certificates (**realm_ca.pem**, **site_ca.pem**) for
trust-store bootstrapping. Supports **tcp://address:port**. The most
specific match wins (node/host override unit overrides site). Disable
the listener by setting **httpd_workers** to 0 (typical when port 80 is
owned by a reverse proxy or ACME http-01 responder).  
Object types: site, unit, node, host

**auth_jwt_valid (time, default: 60s)**  
Validity of JWTs issued for cross-site authentication. When a user
authenticates against one site and then accesses another site within the
same realm, the originating site issues a short-lived JWT that the
remote site uses to verify the authentication. Keep this value short to
limit the window in which a leaked JWT could be replayed. The value
accepts time units (e.g. **60s**, **2m**).  
Object types: site

**sso_jwt_valid (time, default: 24h)**  
Validity of the JWT that the SSO portal (**httpd**) uses to authenticate
against **ssod** on behalf of a logged-in user (for example to register
or delete device tokens). The JWT also defines the lifetime of the
user's SSO browser session: when it expires, the user is logged out of
the SSO portal. Choose a value slightly shorter than the session timeout
of the SSO access group so the JWT, not the access group session, drives
logout. The value accepts time units (e.g. **12h**, **1d**).  
Object types: site

**add_device_token_to_trash (bool, default: true)**  
If true, device tokens that were registered through the SSO portal and
are later deleted via the portal are moved to the trash instead of being
removed permanently. They can be restored from the trash with
**otpme-trash**(1). Set to false to delete such tokens immediately. The
parameter is resolved per user; the most specific match wins (user
overrides unit overrides site).  
Object types: site, unit, user

**reverse_proxy_ips (list)**  
Comma separated list of IP addresses of trusted reverse proxies. When a
request originates from one of these IPs, the **X-Forwarded-For** and
**X-Forwarded-Host** headers are honored to determine the actual client
IP and the requested host. Requests from any other source IP ignore
these headers, so a client cannot spoof its origin by setting them
itself.  
Object types: site

## OIDC Provider

The following parameters apply per OIDC client (with site/unit serving
as the deployment default). For the operational view of the OP --
enabling it, rotating signing keys, the pairwise secret -- see
**otpme-site**(1).

**oidc_default_scopes (list)**  
Comma separated list of scopes auto-granted to RPs without an explicit
Scope-object grant. Names must reference existing **scope** objects.  
Object types: site, unit

**oidc_email_attribute (str, default: mail)**  
LDIF attribute used as the source for the OIDC *email* claim. The
default is the standard inetOrgPerson **mail** attribute; sites that
virtualise mail aliases via **mailLocalAddress** (postfix-virtual /
qmail-style) can override here.  
Object types: site, unit

**oidc_logout_scope (str, default: sso)**  
Behaviour of the OIDC */end_session* endpoint. **sso** performs full
single sign-out and cascades into all child OIDCSessions (firing
backchannel logout to each registered RP). **rp** terminates only the
OIDCSession of the calling RP; the SSO session and other RPs stay logged
in. Useful when high-security RPs want their own, shorter session
lifetime independent of SSO. Valid values: **sso**, **rp**.  
Object types: site, unit, client

**oidc_pkce_required (bool, default: true)**  
Whether PKCE (RFC 7636) is mandatory for the authorize flow. OAuth 2.1
makes PKCE required for all clients, so the default is true. Disable
per-client only for legacy RPs that cannot generate code_verifier /
code_challenge.  
Object types: site, unit, client

**oidc_allow_plain_pkce (bool, default: false)**  
Whether the deprecated PKCE method **plain** is acceptable for the
authorize flow. OAuth 2.1 §7.5.2 forbids **plain** because an attacker
who steals the auth code also has the verifier. The only use case for
true is interop with a legacy RP that hardcodes **plain** and cannot be
upgraded. The discovery document never advertises it regardless.  
Object types: site, unit, client

**oidc_id_token_hint_max_age (time, default: 90d)**  
Maximum age of an **id_token_hint** accepted at */end_session*. We
deliberately do not enforce **exp** -- a user logging out an hour after
the AT expired is a legit case -- but unbounded acceptance would let a
years-old leaked ID Token from a backup still drive a logout. 90 days is
a reasonable default; reduce for higher-assurance deployments. Accepts
human units (e.g. **7D**, **12h**, **2W**).  
Object types: site, unit, client

**oidc_access_token_ttl (time, default: 1h)**  
Lifetime of OIDC access tokens (and the ID Token issued alongside).
Default 1h matches OAuth 2.1 guidance for bearer tokens. High-value RPs
(banking, admin tooling) may set 5m; low-value internal tools may set
8h. Refresh tokens are bounded by the parent SSO session, not by this
TTL. Accepts human units (e.g. **5m**, **1h**, **8h**).  
Object types: site, unit, client

**oidc_acr_scheme (str, default: numeric)**  
Authentication Context Class Reference (*acr*) scheme used in ID Tokens.
**numeric** emits "0" / "1" / "2" per the OIDC Core §2 + ISO/IEC 29115 /
NIST 800-63 conventions (broadest RP support). **none** omits the *acr*
claim entirely; only *amr* (RFC 8176) is included. AMR is always emitted
when an auth_token is known. Valid values: **numeric**, **none**.  
Object types: site, unit, client

**oidc_require_consent (bool, default: false)**  
Whether the OP shows an end-user consent screen at */authorize*. Default
false matches the enterprise-SSO sweet spot: the admin has already gated
per-Scope-allowlist who-can-grant-what; an additional per-user click is
friction for trusted internal RPs. Set true per-client for public-facing
or multi-tenant RPs where the user must explicitly approve data sharing.
Granted consents are remembered per (user, client) trust-on-first-use; a
wider scope request re-prompts. The OIDC **prompt=consent** request
parameter overrides the stored value and always re-shows the screen.  
Object types: site, unit, client

## Share Notifications

**send_share_notifications (bool, default: false)**  
Whether the site sends share-permission notifications to online hosts so
they can react to permission changes immediately (e.g. transient mount /
unmount on enable/disable). The most specific match wins (token
overrides user overrides share overrides unit overrides site).
Per-command **--share-notify** / **--no-share-notify** flags on
**otpme-share**, **otpme-group**, **otpme-role**, **otpme-token**, and
**otpme-user**(1) override this default for a single invocation.  
Object types: site, unit, share, user, token

## Daemon Tuning

**authd_workers (int, default: 16)**  
Number of preforked **authd** worker processes. Increase on busy nodes
to handle more concurrent authentication requests. The most specific
match wins (node overrides unit overrides site).  
Object types: site, unit, node

**httpd_ssl_workers (int, default: 8)**  
Number of preforked **httpd** worker processes serving the SSO portal
over HTTPS. Increase on busy SSO hosts to handle more concurrent TLS
requests. The most specific match wins (node/host override unit
overrides site).  
Object types: site, unit, node, host

**httpd_workers (int, default: 2)**  
Number of preforked worker processes for the plain-HTTP CA-publish
listener bound on **httpd_socket_uri**. Set to 0 to disable the listener
entirely (e.g. when port 80 is owned by a reverse proxy or ACME http-01
responder).  
Object types: site, unit, node, host

**allow_who_from_hosts (bool, default: false)**  
Whether **otpme-tool who** may be invoked from non-node hosts. Default
false restricts the global session view to nodes; set true to allow
ordinary OTPme hosts on the site to query active sessions of the users
that are logged in there. Defense-in-depth: enable only when needed.  
Object types: site

## Connection Limits

Per-daemon ceilings on the number of concurrent client connections
accepted by each daemon. The most specific match wins (node overrides
unit overrides site). Use these to harden a busy node against connection
exhaustion or to deliberately throttle a quiet site. The defaults are
sized for typical deployments — raise them only when traffic actually
demands it.

**mgmtd_max_conn (int, default: 128)**  
Maximum concurrent client connections accepted by **mgmtd**.  
Object types: site, unit, node

**joind_max_conn (int, default: 128)**  
Maximum concurrent client connections accepted by **joind**.  
Object types: site, unit, node

**syncd_max_conn (int, default: 1024)**  
Maximum concurrent client connections accepted by **syncd**.  
Object types: site, unit, node

**ssod_max_conn (int, default: 1024)**  
Maximum concurrent client connections accepted by **ssod**.  
Object types: site, unit, node

**clusterd_max_conn (int, default: 512)**  
Maximum concurrent peer connections accepted by **clusterd**.  
Object types: site, unit, node

**fsd_max_conn (int, default: 1024)**  
Maximum concurrent client connections accepted by **fsd**.  
Object types: site, unit, node

**idled_max_conn (int, default: 1024)**  
Maximum concurrent client connections accepted by **idled**.  
Object types: site, unit, node

**backupd_max_conn (int, default: 256)**  
Maximum concurrent client connections accepted by **backupd**. Also
applies on hosts because a host can act as a backup target that accepts
incoming backup writes.  
Object types: site, unit, node, host

## Request Limits

**max_decompressed_size (size, default: 256M)**  
Hard cap on the size of a single request *after* decompression. Guards
against zip-bomb style payloads that inflate small compressed messages
into memory-exhausting blobs. Each daemon reads this from its own host
object at startup (inherited from unit/site) and enforces it on the
decompress path. Accepts human sizes (e.g. **256M**, **1G**).  
Object types: site, unit, node, host

## Name Length Limits

Per-object-type upper bound on the length of new object names, checked
at add/rename time. Existing objects are not affected. The most specific
match wins (unit overrides site). Tighten these to keep LDAP DNs, file
paths, and CLI output manageable; loosen them only when you know the
downstream consumers can cope. All parameters are ints and apply to
**site**, **unit**.

**max_realm_name_len (int, default: 64)**  
Cap for realm names.

**max_site_name_len (int, default: 32)**  
Cap for site names.

**max_unit_name_len (int, default: 64)**  
Cap for unit names.

**max_user_name_len (int, default: 32)**  
Cap for user names.

**max_token_name_len (int, default: 128)**  
Cap for token names.

**max_group_name_len (int, default: 32)**  
Cap for group names.

**max_role_name_len (int, default: 64)**  
Cap for role names.

**max_accessgroup_name_len (int, default: 64)**  
Cap for access group names.

**max_host_name_len (int, default: 64)**  
Cap for host names.

**max_node_name_len (int, default: 64)**  
Cap for node names.

**max_client_name_len (int, default: 64)**  
Cap for client names.

**max_ca_name_len (int, default: 64)**  
Cap for CA names.

**max_policy_name_len (int, default: 64)**  
Cap for policy names.

**max_resolver_name_len (int, default: 64)**  
Cap for resolver names.

**max_scope_name_len (int, default: 128)**  
Cap for scope names.

**max_script_name_len (int, default: 64)**  
Cap for script names.

**max_share_name_len (int, default: 64)**  
Cap for share names.

**max_pool_name_len (int, default: 64)**  
Cap for pool names.

**max_dictionary_name_len (int, default: 64)**  
Cap for dictionary names.

**max_device_name_len (int, default: 64)**  
Cap for device names.

## Backup

**backup_enabled (bool)**  
Enable or disable backups for this object.  
Object types: site, unit, node, share

**backup_exclude_special (bool)**  
Exclude special files from backup.  
Object types: site, unit, node, share

**backup_server (str)**  
Name of the node or host to use as backup server.  
Object types: site, unit, node, share

**backup_time (str)**  
Backup time window in HH:MM-HH:MM format (e.g. "02:00-03:00").  
Object types: site, unit, node, share

**backup_interval (int)**  
Backup interval (accepts human-readable time values, e.g. 1h, 1D).  
Object types: site, unit, node, share

**backup_key (str)**  
AES key (64-character hex string) for encrypting backups. Automatically
generated if not set.  
Object types: site, unit, node, share

**backup_repo_password (str)**  
Password for authenticating to the backup server.  
Object types: site, unit, node, share

**backup_report_enabled (bool, default: false)**  
Enable e-mail reports about completed backup runs (success and failure).
When disabled, none of the other **backup_report\_\*** parameters take
effect.  
Object types: site, unit, node, share

**backup_report_mode (str, default: all)**  
Which backup runs to report on. Valid values: *all* (report every run),
*success* (only successful runs), *error* (only failed runs).  
Object types: site, unit, node, share

**backup_report_smtp_server (str, default: 127.0.0.1)**  
SMTP server to use when sending backup reports.  
Object types: site, unit, node, share

**backup_report_smtp_port (int, default: 25)**  
TCP port of the SMTP server.  
Object types: site, unit, node, share

**backup_report_smtp_starttls (bool, default: false)**  
Issue **STARTTLS** before sending the report.  
Object types: site, unit, node, share

**backup_report_smtp_auth (bool, default: false)**  
Authenticate to the SMTP server with **backup_report_smtp_username** and
**backup_report_smtp_password**.  
Object types: site, unit, node, share

**backup_report_smtp_username (str)**  
Login name for SMTP authentication.  
Object types: site, unit, node, share

**backup_report_smtp_password (str)**  
Password for SMTP authentication. Stored encrypted with the site key;
shown as *\<hidden\>* by **show_config**.  
Object types: site, unit, node, share

**backup_report_mail_from (str)**  
Envelope and **From:** address of the report e-mail.  
Object types: site, unit, node, share

**backup_report_mail_to (str)**  
Recipient address for the report e-mail.  
Object types: site, unit, node, share

**backup_mode (str, default: pack)**  
Backup storage mode. Valid values: **pack**, **tree**. In **pack** mode,
backup data is stored in pack files (default, more space-efficient). In
**tree** mode, backup data is additionally stored in a directory tree
that mirrors the original file hierarchy. This allows creating a restore
share that can be accessed via FUSE mount.  
Object types: node, share

**backup_excludes (list)**  
Comma-separated list of patterns to exclude from backup.  
Object types: node, share

**backup_includes (list)**  
Comma-separated list of patterns to include in backup.  
Object types: node, share

**backup_script (str)**  
Path of the OTPme script ( *scripts/*unit relative path) run by
**backupd** around each backup. Invoked with a **pre** hook before and a
**post** hook after the backup; non-zero exit aborts the run. Default
points at the bundled **backup_script.sh** in the default scripts unit.
Setting this parameter requires admin.  
Object types: site, unit, share, node

## HOTP Tokens

**hotp_check_range (int, default: 32)**  
Counter check range for HOTP authentication.  
Object types: site, unit, user

**hotp_resync_check_range (int, default: 1024)**  
Counter check range for HOTP token resynchronization.  
Object types: site, unit, user

**hotp_default_pin_len (int, default: 4)**  
Default PIN length for new HOTP tokens.  
Object types: site, unit, user

**hotp_secret_len (int, default: 10)**  
Default secret length in bytes for new HOTP tokens.  
Object types: site, unit, user

## TOTP Tokens

**totp_default_pin_len (int, default: 4)**  
Default PIN length for new TOTP tokens.  
Object types: site, unit, user

**totp_secret_len (int, default: 10)**  
Default secret length in bytes for new TOTP tokens.  
Object types: site, unit, user

## mOTP Tokens

**motp_validity_time (int, default: 60)**  
OTP validity window in seconds for mOTP tokens.  
Object types: site, unit, user

**motp_timedrift_tolerance (int, default: 15)**  
Time drift tolerance in seconds for mOTP tokens.  
Object types: site, unit, user

**motp_default_pin_len (int, default: 4)**  
Default PIN length for new mOTP tokens.  
Object types: site, unit, user

**motp_len (int, default: 6)**  
Length of generated mOTP values.  
Object types: site, unit, user

**motp_secret_len (int, default: 16)**  
Default secret length in bytes for new mOTP tokens.  
Object types: site, unit, user

## Static Password Tokens

**default_static_pass_len (int, default: 10)**  
Default length for generated static passwords.  
Object types: site, unit, user

## Hardware Tokens

**check_fido2_attestation_cert (bool, default: false)**  
If enabled, the FIDO2 attestation certificate is verified during token
deployment.  
Object types: site, unit, user, token

**check_u2f_attestation_cert (bool, default: false)**  
If enabled, the U2F attestation certificate is verified during token
deployment.  
Object types: site, unit, user, token

## OTP Push Tokens

**otp_push_default_pass_len (int, default: 6)**  
Default length of generated OTP push passwords.  
Object types: site, unit, user

**default_otp_push_script (str)**  
Path of the default script used for OTP push delivery.  
Object types: realm, site, unit

## YubiKey HMAC Tokens

**otpme_hmac_otp_len (int, default: 16)**  
OTP length for YubiKey HMAC tokens.  
Object types: site, unit, user

**otpme_hmac_secret_len (int, default: 16)**  
Default secret length in bytes for YubiKey HMAC tokens.  
Object types: site, unit, user

## Hash Parameters (Argon2)

**default_pw_hash_argon2i_iterations (int, default: 3)**  
Argon2i iteration count.  
Object types: site, unit, user, token

**default_pw_hash_argon2i_min_mem (int, default: 65536)**  
Argon2i minimum memory in KB.  
Object types: site, unit, user, token

**default_pw_hash_argon2i_max_mem (int, default: 262144)**  
Argon2i maximum memory in KB.  
Object types: site, unit, user, token

**default_pw_hash_argon2i_threads (int, default: 4)**  
Argon2i thread count.  
Object types: site, unit, user, token

**default_pw_hash_argon2i_key_len (int, default: 128)**  
Argon2i derived key length in bytes.  
Object types: site, unit, user, token

**default_pw_hash_argon2d_iter (int, default: 3)**  
Argon2d iteration count.  
Object types: site, unit, user, token

**default_pw_hash_argon2d_min_mem (int, default: 65536)**  
Argon2d minimum memory in KB.  
Object types: site, unit, user, token

**default_pw_hash_argon2d_max_mem (int, default: 262144)**  
Argon2d maximum memory in KB.  
Object types: site, unit, user, token

**default_pw_hash_argon2d_threads (int, default: 4)**  
Argon2d thread count.  
Object types: site, unit, user, token

**default_pw_hash_argon2d_key_len (int, default: 128)**  
Argon2d derived key length in bytes.  
Object types: site, unit, user, token

## Hash Parameters (PBKDF2)

**default_pw_hash_pbkdf2_iter (int, default: 100000)**  
PBKDF2 iteration count.  
Object types: site, unit, user, token

**default_pw_hash_pbkdf2_algo (str, default: SHA256)**  
PBKDF2 hash algorithm.  
Object types: site, unit, user, token

**default_pw_hash_pbkdf2_key_len (int, default: 128)**  
PBKDF2 derived key length in bytes.  
Object types: site, unit, user, token

## Hash Parameters (HKDF)

**default_pw_hash_hkdf_algo (str, default: SHA256)**  
HKDF hash algorithm.  
Object types: site, unit, user, token

**default_pw_hash_hkdf_key_len (int, default: 32)**  
HKDF derived key length in bytes.  
Object types: site, unit, user, token

# FILES

*/etc/otpme/otpme.conf*  
Main configuration file

*/var/lib/otpme/*  
Data directory (objects, indices, caches)

*/var/log/otpme/*  
Log directory

*\~/.otpme/*  
User-specific configuration and caches

# SEE ALSO

**otpme**(7), **otpme-user**(1), **otpme-token**(1),
**otpme-policy**(1), **otpme-accessgroup**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
