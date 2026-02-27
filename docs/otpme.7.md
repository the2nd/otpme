# OTPME(7)

## NAME

otpme - OTPme authentication and authorization system architecture

## DESCRIPTION

**OTPme**
is a comprehensive authentication and authorization system that provides secure multi-factor authentication, granular access control, and centralized identity management. This manual page describes the overall architecture, core concepts, and design principles of OTPme.

A central design principle of OTPme is that each user can have
**multiple authentication tokens**
assigned simultaneously. Different tokens can be used for different services, allowing fine-grained control over how a user authenticates to each resource.

For example, consider WLAN authentication: instead of sharing a single password across all of a user's devices, an administrator can assign a separate password token for each device (laptop, phone, tablet). If a device is stolen, the administrator simply deletes that device's token. All other devices continue to work without any reconfiguration - there is no need to change the WLAN password on every remaining device.

This per-service token design also provides strong security isolation. Since each token only grants access to the service it is assigned to, someone who obtains a user's WLAN password cannot use it to access the user's email, file shares, or system login. Each service is protected by its own independent credentials.

A user might log in to their workstation with a FIDO2 hardware key, access file shares with the same FIDO2 token, authenticate to WLAN with per-device passwords via RADIUS, and use a dedicated password token for groupware access (CalDAV, CardDAV, IMAP) from a smartphone where credentials are stored persistently on the device - all managed centrally under one identity.

Access control is enforced through
**clients**
and
**access groups.**
Each service that authenticates against OTPme is represented as a client object. An access group is assigned to each client, and only tokens or roles that are members of that access group are permitted to authenticate.

A client can be a
**RADIUS client,**
where the RADIUS NAS identifier must match the OTPme client name. For example, a WLAN access point configured with NAS ID "wlan-office" must have a corresponding OTPme client named "wlan-office". Only tokens assigned to that client's access group will be accepted for WLAN authentication.

Alternatively, a client can be an
**LDAP client,**
authenticating against
otpme-ldapd.
In this case the client name is specified as a DC component in the LDAP bind DN. For example, a bind DN of
*uid=user1,ou=users,dc=mailserver,dc=example,dc=com*
maps to the OTPme client "mailserver". This way, the mail server can only authenticate users who hold tokens assigned to the mail server's access group.

## ARCHITECTURE OVERVIEW

OTPme is built on a distributed, hierarchical architecture with the following key components:

### Daemons

**controld**
:   Main daemon controller. Starts, stops, and monitors all other OTPme daemons.

**mgmtd**
:   Management daemon. Handles all administrative operations such as creating, modifying, and deleting objects (users, tokens, policies, etc.).

**authd**
:   Authentication daemon. Handles authentication requests, validates credentials, and manages sessions.

**syncd**
:   Synchronization server daemon. Serves objects from all sites to hostd instances. On nodes, objects from other sites are synchronized between hostd and syncd. Objects from the local site are synchronized between nodes by the clusterd.

**hostd**
:   Host daemon. Runs on both hosts and nodes. Acts as a sync client that pulls object updates from a node's syncd. On hosts, hostd synchronizes objects from all sites with the syncd on nodes.

**clusterd**
:   Cluster daemon. Manages cluster coordination, quorum, and master failover between nodes within a site. Also handles synchronization of local site objects between nodes.

**joind**
:   Join daemon. Handles the process of joining a host or node to an OTPme site.

**ldapd**
:   LDAP daemon. Provides an LDAP interface so that external services can authenticate users and query directory data against OTPme.

**httpd**
:   HTTP daemon. Serves the web management interface.

**fsd**
:   File server daemon. Handles file share access for FUSE-mounted OTPme shares.

**scriptd**
:   Script daemon. Executes server-side scripts (e.g. authentication scripts, push scripts).

### External Integrations

**FreeRADIUS**
:   OTPme integrates with FreeRADIUS to provide RADIUS authentication (e.g. WLAN, VPN). OTPme includes a FreeRADIUS module (rlm_python) that forwards RADIUS requests to the authd. Alternatively, FreeRADIUS can use the
**otpme-auth**
command, which serves as a replacement for ntlm_auth. Any application that supports RADIUS (e.g. via pam_radius_auth) can authenticate against OTPme.

**PAM Module**
:   OTPme includes a Python PAM module that enables authentication with token types such as FIDO2 or YubiKey HMAC challenge-response during system login. Upon login, the
**otpme-agent**
is started to manage a realm session and connections to the mgmtd. Through the otpme-agent, users can manage OTPme objects (users, groups, tokens, etc.) and access file shares served by the fsd without re-authenticating.

**NSS (libnss-cache)**
:   OTPme uses libnss-cache to make OTPme users and groups available as local Linux accounts. The cache files are generated by the hostd using nsscache.

## ORGANIZATIONAL STRUCTURE

OTPme organizes infrastructure in a three-level hierarchy:

### Realms

A
**realm**
is the top-level administrative domain, comparable to a Windows domain. It represents a completely independent authentication domain with its own users, groups, policies, roles, units, and other objects. Realms are currently completely independent and cannot be connected to each other.

A realm contains one or more sites. Users and groups are realm-wide, meaning they exist across all sites. Other objects such as units, roles, and policies are per-site. The only user that exists per-site is the root user.

### Sites

A
**site**
is a separate administrative area within a realm. Typically, a site is created for each physical location. Since the nodes of a site form a cluster, this provides redundancy per location. Each site has its own root user who can manage the site's users, groups, and other objects. Additionally, each site has a
**site_admin**
role that can be assigned to a "user/token" to grant administrative rights for that site. Normal users can be granted specific modify rights on objects via ACLs, including across sites.

By default, token secrets are not synchronized to other sites. When a user from site1 tries to log in on a host belonging to site2, the authentication request is forwarded to site1. To allow local authentication without forwarding, site1 must be configured to trust site2 (site trust). With trust enabled, token secrets are replicated to the trusted site, allowing direct local authentication.

Depending on the use case, users can either be created per-site or centrally in the master site with a site trust configured. Creating users per-site allows independent administration at each location, while creating all users in the master site with trust provides centralized administration.

Nodes and hosts are created per-site but must have realm-wide unique names. The nodes of each site form a cluster.

### Units

**Units**
are comparable to LDAP OUs and are used to store objects. Policies and ACLs can be assigned to a unit - for example, ACLs to allow a token or role to create, delete, or edit objects within the unit, or policies that determine which groups and roles a "user/token" belongs to.

## CORE OBJECT TYPES

### Users

User accounts represent identities that can authenticate to the system. Each user has a unique user ID (username) and gets assigned a unique UID (Unix user ID).

Every user has a default token (login) for authenticating to the realm. Additional tokens can be added for specific services - for example, separate password tokens for WLAN access on a notebook and smartphone.

Each user has a default group. The group is not added to the user - instead, the user is added to the group as a "default group user". This prevents an administrator of site1 from assigning a group from site2 to a user on site1.

Policies and ACLs can also be assigned to a user - for example, ACLs that allow another "user/token" to edit the user, or a policy that determines in which unit objects (e.g. groups) are created by default.

Extensions can be added to a user. By default, the extensions "base" and "posix" are assigned. Both are LDAP extensions that define which LDAP attributes are available for the user.

### Tokens

Tokens are authentication credentials assigned to users. OTPme supports diverse token types:
**TOTP/HOTP**
- RFC 6238/4226 one-time passwords
**FIDO2**
- Hardware security keys and platform authenticators
**U2F**
- Universal 2nd Factor security keys
**SSH**
- Public key authentication
**Password**
- Static passwords with policy enforcement
**YubiKey**
- HMAC-SHA1 challenge-response
**Link**
- Reference to another user's token
**Script**
- Custom authentication via external scripts

A key concept in OTPme is that tokens - not users - are added to groups and roles. Typically, it is the user's default token (login) that is assigned to groups and roles.

Tokens support offline authentication, allowing secure access when the OTPme server is unreachable.

### Groups

A group in OTPme is automatically a Linux group on hosts and nodes, so it can be used to assign filesystem permissions. To add a user to a group, the user's default token is added to the group. Alternatively, the default token can be added to a role, and the role is then added to the group.

There is a built-in group "realmusers" that automatically contains all users of the realm. Additionally, each site has a group named after the site (e.g. "berlin") that automatically contains all users of that site.

Groups can also be used as sync groups to control which users are synchronized to a host.

### Roles

A role is essentially a group of tokens. In almost all places where a token can be assigned, a role can be used instead. This extends and simplifies permission management. Roles can also be added to other roles, enabling hierarchical permission structures.

There are built-in default roles:
**REALM_USER**
and
**SITE_ADMIN.**
By default, every user's default token is added to the REALM_USER role. This allows the user to log in to the realm and automatically makes them a member of the "realmusers" group and the corresponding site group. Adding a "user/token" to the SITE_ADMIN role grants site administrator privileges.

A good example of how roles work: a role "wlan" grants WLAN access, and a role "employee" is added to the role "wlan". Every employee automatically gets WLAN access. A role "marketing" can then be added to the role "employee" and also to the group "marketing". Adding a marketing user's default token to the role "marketing" gives them both WLAN access and membership in the marketing group. If all employees should later get access to an additional service (e.g. webmail), only the role "employee" needs to be added to the corresponding access group (see Access Groups) and the permission is granted for all employees.

### Access Groups

Access groups are used to control access to services and to define session parameters. A client (RADIUS, LDAP) is assigned an access group - for example, the access point "ap01" gets the access group "wlan". Tokens or roles are then assigned to the access group to grant access to the service. When a WLAN authentication request arrives, the access group determines who is allowed access.

Additional parameters can be configured per access group, such as how many failed authentication attempts lock a user out of the access group and for how long (e.g. 5 minutes).

Each access group can be configured to create a session for requests. This is useful when a service sends recurring requests with the same password or OTP (e.g. an IMAP server). Note that an OTP login is then no longer one-time but remains valid for the duration of the session. Per access group, the session lifetime and the maximum number of parallel sessions can be configured.

Access groups can have child access groups. For example, the default access group "SSO" (the OTPme SSO portal) can have "nextcloud" as a child access group. Tokens and roles that have access to the SSO access group then automatically get access to the nextcloud access group as well.

### File Shares

OTPme file shares require a shared storage backend mounted on all nodes (e.g. under /otpme-mounts/ or /otpme-mounts/share1). The mount point is assigned to the share as its root_dir. It is important that this backend is made available on all nodes equally. CephFS or NFS is recommended as backend.

Tokens or roles are assigned to a share to grant access. Clients mount shares via FUSE using
otpme-mount.
By default, all nodes serve a share. Specific nodes can be assigned to a share, in which case only those nodes will serve it. The client/host mounts the share from a random node (load balancing).

A share can optionally be created as an encrypted share. During creation, a master password is requested from which the AES key is derived. Since encryption happens on the client/host side, an encrypted copy of the AES key must be added for each token that should access the encrypted share. This is also the reason why only tokens - not roles - can be assigned to an encrypted share.

### Node Pools

A node pool is a collection of nodes. A node pool can be assigned to a share, and then the share is only served by the nodes in that pool.

### Policies

Policies implement business rules and security controls. They can be attached to various objects such as units, users, tokens, or access groups.

**authonaction**
:   Requires re-authentication when performing sensitive actions (e.g. modify, delete, add ACL). Configurable timeout and expiry. Tokens and roles can be whitelisted.

**autodisable**
:   Automatically disables objects after a specified time (e.g. +1h, +1D, +1W, +1M, +1Y). Can optionally count from last usage instead of assignment time.

**defaultgroups**
:   Automatically assigns new users to preconfigured groups upon creation. Can also set the default group of a user.

**defaultpolicies**
:   Automatically attaches preconfigured policies to new objects of a given type.

**defaultroles**
:   Automatically assigns preconfigured roles to the default token of new users.

**defaultunits**
:   Specifies default units for different object types, controlling where new objects are placed.

**forcetoken**
:   Restricts which token types and authentication methods can be used for authorization.

**idrange**
:   Defines ID ranges for automatic assignment of the LDAP attributes uidNumber and gidNumber. Supports sequential and random allocation.

**logintimes**
:   Restricts login to specific times using a cron-like format (e.g. work hours only, weekdays only).

**objecttemplates**
:   Automatically applies template objects (preconfigured settings) to new users or hosts.

**password**
:   Enforces password and PIN strength requirements (minimum length, character complexity, dictionary-based strength checking).

**tokenacls**
:   Automatically assigns ACLs to new tokens, controlling what users and creators can do with them.

## ACCESS CONTROL

OTPme implements a sophisticated multi-layer access control system:

### ACLs (Access Control Lists)

Fine-grained permissions controlling who can perform what operations on which objects. ACLs are assigned to a "user/token" or a role. ACLs support:
Object-specific permissions (view, modify, delete, enable, disable)
Sub-type permissions - e.g. "enable:object" grants enabling the object itself, while "enable" without a sub-type grants all enable permissions (enable:object, enable:mschap, etc.)
Inheritance from parent objects (e.g. ACLs on a unit apply to all objects within)

## OFFLINE AUTHENTICATION

When the OTPme server is unreachable, hosts can authenticate users against locally cached offline data. Offline authentication must be explicitly enabled per token.

During an online login, the token configuration and session data are encrypted and cached locally on the host. The offline data is encrypted using Argon2i key derivation based on the user's password, PIN, or smartcard response.

When the server is unreachable, credentials are verified against the local cache. Already used OTPs are tracked locally to prevent replay attacks. Configurable expiration times control how long the offline cache remains valid (by login age and by inactivity).

When the server becomes available again, the hostd synchronizes used OTPs and token counters back to the server.

## CONFIG PARAMETERS

Configuration parameters are set per-object using the **config** command and displayed with **show_config**.
Parameters set on a parent object (e.g. site or unit) act as defaults for all child objects unless overridden locally.
The column *Object types* lists on which object types each parameter can be set.

**otpme-site config mysite parameter [*value*]**
  
**otpme-site config -d mysite parameter**

### General

**confirmation_policy (str, default: paranoid)**
:   Controls when OTPme asks for user confirmation.
Valid values: **paranoid** (ask for almost anything), **normal** (ask in important cases, e.g. when deleting an object will also delete child objects), **force** (never ask for confirmation).
  
Object types: all tree objects

**auto_sign (bool, default: false)**
:   If enabled, the user is offered to sign the object after each change.
  
Object types: site, unit, token, script

**auto_revoke (bool, default: true)**
:   If enabled, object signatures are automatically revoked when the object is changed.
  
Object types: site, unit, token, script

### Key Backup

**private_key_backup_key (str)**
:   Public RSA key (base64-encoded) used for encryption of user private key backups. If not set, a new key pair is generated automatically.
  
Object types: site, unit

**private_key_backup_key_len (int, default: 2048)**
:   RSA key length for the private key backup key. Valid values: 2048, 4096.
  
Object types: site, unit

### Password Hashing

**default_pw_hash_type (str, default: Argon2_i)**
:   Default hash algorithm for new password tokens. Available types depend on registered hash modules (e.g. Argon2_i, Argon2_d, PBKDF2, HKDF).
  
Object types: site, unit, user, token

**session_hash_type (str, default: Argon2_i)**
:   Hash algorithm used for session passwords.
  
Object types: site, unit, user, token

### Session

**static_pass_timeout (int, default: 15)**
:   Timeout in minutes for static password sessions.
  
Object types: site, unit, host, node

**static_pass_unused_timeout (int, default: 5)**
:   Timeout in minutes for unused static password sessions.
  
Object types: site, unit, host, node

### User Scripts

**default_key_script (str)**
:   Path of the default key script added to new users.
  
Object types: site, unit

**default_auth_script (str)**
:   Path of the default auth script added to new users.
  
Object types: site, unit

**default_agent_script (str)**
:   Path of the default agent script added to new users.
  
Object types: site, unit

**default_login_script (str)**
:   Path of the default login script added to new users.
  
Object types: site, unit

### User Management

**failed_pass_history (int, default: 16)**
:   Number of failed login passwords to remember. Multiple failed login attempts with the same wrong password do not count as separate failures and will not lock the account.
  
Object types: site, unit, user

**add_default_token (bool, default: true)**
:   If enabled, a default token is automatically created for new users.
  
Object types: site, unit

**default_token_name (str, default: login)**
:   Name of the default token created for new users.
  
Object types: site, unit

**default_token_type (str, default: hotp)**
:   Token type of the default token created for new users.
  
Object types: site, unit

**user_key_len (int, default: 2048)**
:   RSA key length for user keys. Valid values: 2048, 4096.
  
Object types: realm, site, unit, user

**allow_default_token_rename (bool, default: false)**
:   If enabled, users are allowed to rename their default token.
  
Object types: site, unit, user

**allow_default_token_deletion (bool, default: false)**
:   If enabled, users are allowed to delete their default token.
  
Object types: site, unit, user

**allow_temp_paswords (bool, default: false)**
:   If enabled, temporary passwords can be set on tokens.
  
Object types: site, unit, user, token

**password_allowed_chars (str, default: 0-9A-Za-z!@#$%^&*()_+-={}[]|\\:;<>.?/)**
:   Character set allowed in passwords (used by the password policy).
  
Object types: site, unit, user

### Certificates

**cert_key_len (int, default: 2048)**
:   RSA key length for CA-issued certificates. Valid values: 2048, 4096.
  
Object types: site, unit, ca

**cert_sign_algo (str, default: sha256)**
:   Signature algorithm for certificates. Valid values: sha256, sha512.
  
Object types: site, unit, ca

**crl_sign_algo (str, default: sha256)**
:   Signature algorithm for certificate revocation lists. Valid values: sha256, sha512.
  
Object types: site, unit, ca

### File Shares

**default_share_add_script (str)**
:   Path of the default script used when adding new shares.
  
Object types: site, unit

**default_share_mount_script (str)**
:   Path of the default script used to mount shares.
  
Object types: site, unit

**share_root (str, default: /otpme-mounts/)**
:   Root directory for new shares. A new share automatically gets *share_root*/*sharename* as its root directory (e.g. with **share_root=/otpme-mounts/** a share named **projects** gets **/otpme-mounts/projects** as its root directory).
  
Object types: site, unit

### HOTP Tokens

**hotp_check_range (int, default: 32)**
:   Counter check range for HOTP authentication.
  
Object types: site, unit, user

**hotp_resync_check_range (int, default: 1024)**
:   Counter check range for HOTP token resynchronization.
  
Object types: site, unit, user

**hotp_default_pin_len (int, default: 4)**
:   Default PIN length for new HOTP tokens.
  
Object types: site, unit, user

**hotp_secret_len (int, default: 10)**
:   Default secret length in bytes for new HOTP tokens.
  
Object types: site, unit, user

### TOTP Tokens

**totp_default_pin_len (int, default: 4)**
:   Default PIN length for new TOTP tokens.
  
Object types: site, unit, user

**totp_secret_len (int, default: 10)**
:   Default secret length in bytes for new TOTP tokens.
  
Object types: site, unit, user

### mOTP Tokens

**motp_validity_time (int, default: 60)**
:   OTP validity window in seconds for mOTP tokens.
  
Object types: site, unit, user

**motp_timedrift_tolerance (int, default: 15)**
:   Time drift tolerance in seconds for mOTP tokens.
  
Object types: site, unit, user

**motp_default_pin_len (int, default: 4)**
:   Default PIN length for new mOTP tokens.
  
Object types: site, unit, user

**motp_len (int, default: 6)**
:   Length of generated mOTP values.
  
Object types: site, unit, user

**motp_secret_len (int, default: 16)**
:   Default secret length in bytes for new mOTP tokens.
  
Object types: site, unit, user

### Static Password Tokens

**default_static_pass_len (int, default: 10)**
:   Default length for generated static passwords.
  
Object types: site, unit, user

### Hardware Tokens

**check_fido2_attestation_cert (bool, default: false)**
:   If enabled, the FIDO2 attestation certificate is verified during token deployment.
  
Object types: site, unit, user, token

**check_u2f_attestation_cert (bool, default: false)**
:   If enabled, the U2F attestation certificate is verified during token deployment.
  
Object types: site, unit, user, token

### OTP Push Tokens

**otp_push_default_pass_len (int, default: 6)**
:   Default length of generated OTP push passwords.
  
Object types: site, unit, user

**default_otp_push_script (str)**
:   Path of the default script used for OTP push delivery.
  
Object types: realm, site, unit

### YubiKey HMAC Tokens

**otpme_hmac_otp_len (int, default: 16)**
:   OTP length for YubiKey HMAC tokens.
  
Object types: site, unit, user

**otpme_hmac_secret_len (int, default: 16)**
:   Default secret length in bytes for YubiKey HMAC tokens.
  
Object types: site, unit, user

### Hash Parameters (Argon2)

**default_pw_hash_argon2i_iterations (int, default: 3)**
:   Argon2i iteration count.
  
Object types: site, unit, user, token

**default_pw_hash_argon2i_min_mem (int, default: 65536)**
:   Argon2i minimum memory in KB.
  
Object types: site, unit, user, token

**default_pw_hash_argon2i_max_mem (int, default: 262144)**
:   Argon2i maximum memory in KB.
  
Object types: site, unit, user, token

**default_pw_hash_argon2i_threads (int, default: 4)**
:   Argon2i thread count.
  
Object types: site, unit, user, token

**default_pw_hash_argon2i_key_len (int, default: 128)**
:   Argon2i derived key length in bytes.
  
Object types: site, unit, user, token

**default_pw_hash_argon2d_iter (int, default: 3)**
:   Argon2d iteration count.
  
Object types: site, unit, user, token

**default_pw_hash_argon2d_min_mem (int, default: 65536)**
:   Argon2d minimum memory in KB.
  
Object types: site, unit, user, token

**default_pw_hash_argon2d_max_mem (int, default: 262144)**
:   Argon2d maximum memory in KB.
  
Object types: site, unit, user, token

**default_pw_hash_argon2d_threads (int, default: 4)**
:   Argon2d thread count.
  
Object types: site, unit, user, token

**default_pw_hash_argon2d_key_len (int, default: 128)**
:   Argon2d derived key length in bytes.
  
Object types: site, unit, user, token

### Hash Parameters (PBKDF2)

**default_pw_hash_pbkdf2_iter (int, default: 100000)**
:   PBKDF2 iteration count.
  
Object types: site, unit, user, token

**default_pw_hash_pbkdf2_algo (str, default: SHA256)**
:   PBKDF2 hash algorithm.
  
Object types: site, unit, user, token

**default_pw_hash_pbkdf2_key_len (int, default: 128)**
:   PBKDF2 derived key length in bytes.
  
Object types: site, unit, user, token

### Hash Parameters (HKDF)

**default_pw_hash_hkdf_algo (str, default: SHA256)**
:   HKDF hash algorithm.
  
Object types: site, unit, user, token

**default_pw_hash_hkdf_key_len (int, default: 32)**
:   HKDF derived key length in bytes.
  
Object types: site, unit, user, token

## FILES

*/etc/otpme/otpme.conf*
:   Main configuration file

*/var/lib/otpme/*
:   Data directory (objects, indices, caches)

*/var/log/otpme/*
:   Log directory

*~/.otpme/*
:   User-specific configuration and caches

## SEE ALSO

[otpme(7)](otpme.7.md),
[otpme-user(1)](otpme-user.md),
[otpme-token(1)](otpme-token.md),
[otpme-policy(1)](otpme-policy.md),
[otpme-accessgroup(1)](otpme-accessgroup.md)

## AUTHOR

the2nd <the2nd@otpme.org>

## NOTE

This manual page was created with AI assistance.

## COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
