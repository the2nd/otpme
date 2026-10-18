# NAME

otpme - OTPme authentication and authorization system architecture

# DESCRIPTION

**OTPme** is a system for authentication and authorization. It supports
multi-factor authentication, access control per service, and central
management of users and their tokens. This page describes how OTPme is
built and its main concepts.

A main idea of OTPme is that each user can have **many authentication
tokens** at the same time. Different tokens can be used for different
services. So you decide for each service how a user logs in to it.

An example is WLAN. Instead of one password on all devices of a user,
the administrator gives each device its own password token (laptop,
phone, tablet). If a device is stolen, the administrator deletes the
token of this device. All other devices keep working. There is no need
to change the WLAN password on the other devices.

This also keeps the services apart. A token only gives access to the
services it is assigned to. Someone who gets the WLAN password of a user
can not use it for the user's mail, file shares or system login. Each
service has its own credentials.

For example, a user can log in to the workstation with a FIDO2 key and
use the same FIDO2 token for file shares. The same user can use WLAN
with one password per device (RADIUS), and a separate password token for
groupware (CalDAV, CardDAV, IMAP) on a smartphone that stores the
password. All of this is managed in one place, for one user.

Access is controlled with **clients** and **access groups**. Each
service that uses OTPme for authentication is a client object. Each
client has an access group. Only tokens and roles in this access group
can log in to the service.

A client can be a **RADIUS client**. The RADIUS NAS identifier must be
the same as the name of the OTPme client. For example, a WLAN access
point with the NAS ID "wlan-office" needs an OTPme client named
"wlan-office". Only tokens in the access group of this client are
accepted for WLAN.

A client can also be an **LDAP client**, which uses **otpme-ldapd**.
Here the client name is a DC part of the LDAP bind DN. For example, the
bind DN

> *uid=user1,ou=users,dc=mailserver,dc=example,dc=org*

selects the OTPme client "mailserver". So the mail server can only log
in users with a token in the access group of the mail server.

OTPme has an **SSO web portal**. Users log in there once and can then
open the connected web applications without a new login. The portal also
has self service, so users can manage their own login methods:

-   account recovery, for example with a recovery mail address

-   device tokens: a separate password for each device, for example for
    WLAN or groupware

-   FIDO2 security keys and passkeys

-   TOTP tokens (authenticator apps)

-   tiqr tokens

-   a profile page with the user's photo and data. The administrator
    decides which data users can change themselves
    (**sso_allow_profile_edit**).

A client can also be an **OIDC client** of the SSO portal, for example
Nextcloud. The web application sends its users to the OTPme SSO portal
to log in (OpenID Connect). Such a client is created with
**--enable-oidc**, see **otpme-client**(1). Here too, only tokens and
roles in the access group of the client can log in.

# ARCHITECTURE OVERVIEW

OTPme runs as a set of daemons. **otpme-controld** starts them. Nodes
run all daemons. Hosts only run hostd and confd, and httpd or backupd if
they are configured as SSO or backup server.

## Daemons

**controld**  
Starts, stops and watches all other OTPme daemons.  
Runs on: nodes and hosts.

**mgmtd**  
Management daemon. It handles all changes to objects, for example
adding, changing or deleting users, tokens and policies.  
Runs on: nodes.

**authd**  
Authentication daemon. It checks logins and credentials and manages
login sessions.  
Runs on: nodes.

**syncd**  
Sync server. It sends objects to the hostd of hosts and of the nodes of
other sites.  
Runs on: nodes.

**hostd**  
Sync client. It gets object changes from the syncd of the nodes. On a
node it syncs the objects of other sites; the objects of the own site
are synced by clusterd.  
Runs on: nodes and hosts.

**clusterd**  
Cluster daemon. It manages the nodes of a site: quorum, the master node
and failover. It also syncs the objects of the own site between the
nodes. See **otpme-cluster**(1).  
Runs on: nodes.

**joind**  
Join daemon. It handles hosts and nodes that join the site.  
Runs on: nodes.

**ldapd**  
LDAP server. Other services can check logins and read directory data
with LDAP.  
Runs on: nodes. It is started by clusterd when the cluster has quorum
and the node is in sync, and stopped when the quorum is lost.

**httpd**  
Web server for the SSO portal (see DESCRIPTION) and for the site
certificates (*/certs*).  
Runs on: nodes, and hosts with **SSO_SERVER** set in **otpme.conf**(5).

**ssod**  
SSO daemon. It does the work behind the SSO portal: logins, OIDC tokens
and tiqr. The web server talks to it over a local socket.  
Runs on: nodes.

**fsd**  
File server for OTPme file shares, which clients mount with FUSE.  
Runs on: nodes.

**scriptd**  
Runs scripts on the server, for example authentication scripts and push
scripts.  
Runs on: nodes.

**backupd**  
Runs backups.  
Runs on: nodes, and hosts with **BACKUP_SERVER** set in
**otpme.conf**(5).

**idled**  
Sends events to the **otpme-agent** of logged in users, for example that
a share can be mounted.  
Runs on: the master node only. clusterd starts it on the new master node
when the master changes.

**confd**  
Configuration daemon. It runs as root. It gets signed configuration jobs
from the nodes, checks them and runs them. See **otpme-deploy**(1). It
also reports the system, the kernel, the packages and the hardware of
the host to the nodes, and whether the host has to be rebooted. See
**otpme-inventory**(1).  
Runs on: nodes and hosts.

## External Integrations

**FreeRADIUS**  
RADIUS logins, for example for WLAN and VPN. OTPme comes with a
FreeRADIUS module (rlm_python) that sends the RADIUS requests to authd.
FreeRADIUS can also use the command **otpme-auth** instead of ntlm_auth.
Every application that supports RADIUS (for example with
pam_radius_auth) can use OTPme for logins.

**LDAP**  
**ldapd** is an LDAP server. Services like Nextcloud or a mail server
can check logins and read users and groups with LDAP. The client name in
the bind DN selects the OTPme client, see DESCRIPTION.

**OpenID Connect**  
The SSO portal is an OpenID Connect provider. Web applications like
Nextcloud use it to log in their users. See **--enable-oidc** in
**otpme-client**(1).

**tiqr**  
Login with the tiqr app on a smartphone. Users add a tiqr token in the
SSO portal and confirm logins in the app.

**SSH**  
SSH keys can be stored in OTPme and assigned to hosts.
**otpme-get-authorized-keys** *user* prints the keys of a user for this
host. Use it as **AuthorizedKeysCommand** in sshd.

**PAM Module**  
System login on hosts and nodes, see **pam_otpme**(8). It works with
password and OTP tokens and with hardware tokens like FIDO2 keys and
YubiKeys (HMAC, PIV). After the login the **otpme-agent** is started. It
keeps the OTPme login session. With it, users can manage OTPme objects
and use the file shares of fsd without logging in again.

**NSS (libnss-cache)**  
OTPme users and groups are available as local Linux accounts through
libnss-cache. hostd writes the cache files with nsscache.

## Recommended Token Type

The recommended token type is **yubikey_piv** (a YubiKey with the PIV
applet). The sign key and the encrypt key of the user are stored on the
YubiKey. They can not be read from it, so they can not be copied from
the computer either. With them the user can safely:

-   use encrypted file shares

-   sign scripts, tokens and configuration jobs (see
    **otpme-deploy**(1))

-   log in to the network with 802.1X port authentication. **pam_otpme**
    creates a one-time password with the YubiKey at login and connects
    the LAN port with it, before the network is needed for the login.
    See **do_dot1x** in **pam_otpme**(8).

The keys of the YubiKey only become the keys of the user if you deploy
the token with **--add-user-key**:

> **otpme-token --type yubikey_piv deploy --add-user-key alice/piv**

When the token is deployed, a backup of the keys is written. With it a
lost YubiKey can be replaced. See **Deploy - YubiKey PIV Applet** in
**otpme-token**(1).

# ORGANIZATIONAL STRUCTURE

OTPme has three levels: realms, sites and units.

## Realms

A **realm** is the top level, like a Windows domain. It has its own
users, groups, roles, policies, units and other objects. Realms are
independent from each other and can not be connected.

A realm has one or more sites. Each user and each group belongs to one
site, its home site, and is visible in all sites of the realm. Other
objects, for example units, roles and policies, only exist in their
site.

## Sites

A **site** is a part of a realm with its own administration. Usually
there is one site per location. The nodes of a site form a cluster, so
each location has its own redundancy.

Each site has its own root user, who manages the users, groups and other
objects of the site. Each site also has the role **SITE_ADMIN**. Add a
token to this role to give its user admin rights for the site. Other
users can get rights for single objects with ACLs, also in other sites.

Token secrets are not synced to other sites by default. When a user of
site *berlin* logs in on a host of site *munich*, munich redirects the
login to berlin. If berlin trusts munich (site trust), the token secrets
of berlin are synced to munich, and munich can check the login itself.
Add a trust with

> **otpme-site add_trust *berlin* *munich***

or with **--trust** when you add the site, see **otpme-site**(1).

Users can be created in each site, or all in the master site. Users in
each site allow each location to manage its own users. All users in the
master site give one central administration.

A site trust is not needed for central users, but without it a slave
site can not check logins itself. If it can not reach the master site,
nobody can log in there. With a trust the slave site has the token
secrets and logins keep working.

Nodes and hosts belong to one site, but their names must be unique in
the whole realm. New sites can only be added by the master site.

## Sub-Sites

A **sub-site** belongs to another site, its parent site. Its name starts
with the name of the parent site and a dot, for example **berlin.files**
for the parent site **berlin**. The CA of the sub-site is signed by the
CA of the parent site. A sub-site is added from its parent site, not
from the master site.

Otherwise a sub-site is a normal site. It is meant as a separate place
for file shares. The admins of the sub-site decide who can use its
shares, not the admins of the parent site.

With SOTP signing (see **otpme-share**(1)), the admins of the parent
site also can not create a login session for a user and use it to open
the shares of the sub-site: the login must be signed with the user's own
sign key, for example on a YubiKey PIV.

## Units

**Units** are like LDAP OUs. They hold objects. You can add ACLs and
policies to a unit, for example:

-   ACLs that allow a token or role to add, change or delete objects in
    the unit

-   the policies **defaultgroups** and **defaultroles**, which add new
    users to groups and their default token to roles, see
    **otpme-policy**(1)

# CORE OBJECT TYPES

## Users

A user is an identity that can log in. Each user has a unique name and a
unique UID (Unix user ID).

Every user has a default token, named *login*. It is used to log in to
the realm. More tokens can be added for single services, for example one
password token for the WLAN of the notebook and one for the smartphone.

Each user has a default group. The group is not added to the user; the
user is added to the group as a "default group user". So an admin of
site *berlin* can not give a user of berlin a group of site *munich*.

Users can also have policies and ACLs, for example an ACL that lets
another user or token change this user, or a policy that says in which
unit new objects of the user are created.

A user can have extensions. By default a user has the extensions *base*
and *posix*. Extensions say which LDAP attributes a user has, for
example the mail address (base) or **uidNumber** and the home directory
(posix).

## Tokens

A token is what a user logs in with. There are these token types:

-   **password** - a static password. Password policies apply to it.

-   **totp** - one-time password by time (RFC 6238), for example from an
    authenticator app.

-   **hotp** - one-time password by counter (RFC 4226).

-   **motp** - mobile OTP (mOTP): the app makes the one-time password
    from a PIN and a secret.

-   **otp_push** - the one-time password is sent to the user (push).

-   **fido2** - hardware security keys and platform authenticators.

-   **passkey** - a passkey: the key stays on the device, the user logs
    in without a password.

-   **u2f** - older security keys (Universal 2nd Factor).

-   **yubikey_hmac** - YubiKey with HMAC-SHA1 challenge-response.

-   **yubikey_piv** - YubiKey with the PIV applet. The sign key and the
    encrypt key of the user are on the token. This is the recommended
    token type, see **Recommended Token Type** above.

-   **ssh** - login with an SSH key.

-   **tiqr** - the user confirms the login in the tiqr app on a
    smartphone.

-   **link** - points to a token of another user, so that token can be
    used here too.

-   **script_otp** - a script checks the one-time password.

-   **script_static** - a script checks a static password.

Only **yubikey_piv** keeps the keys of the user on hardware. For every
other token type the private keys of the user are stored in OTPme,
protected by the user's key password. So **yubikey_piv** is the only
token type that gives safe access to encrypted shares.

SOTP signing works for shares and access groups, see **otpme-share**(1)
and **otpme-accessgroup**(1). A stored key can be used for it, but then
everything depends on the key password of the user: an admin who
controls the nodes gets the encrypted key, and a weak key password can
be broken. With **yubikey_piv** there is no key to take.

For mgmtd, SOTP signing only works with **yubikey_piv**. A stored key
comes from mgmtd itself, and mgmtd would already ask for a signed SOTP
before it hands the key out.

With **password** it is also the only token type that can do 802.1X port
authentication.

In OTPme, tokens are added to groups and roles, not users. Usually this
is the default token (*login*) of a user.

Tokens can also be used offline, so a user can still log in when the
OTPme server can not be reached.

## Groups

A group of OTPme is also a Linux group on hosts and nodes, so you can
use it for file permissions. The group reaches a host through the sync:
hostd writes the users and groups of the host into the NSS cache (see
**NSS** above). For this the group needs the *posix* extension, which
new groups have by default.

To put a user into a group, add the default token of the user to the
group. You can also add the token to a role and the role to the group.

There is a group *realmusers* with all users of the realm. Each site
also has a group with the name of the site, for example *berlin*, with
all users of that site.

Groups can also be used as sync groups. They then say which users are
synced to a host.

## Dynamic Groups

A dynamic group is a local group on the host, not an OTPme group. OTPme
does not create it. It has to exist on the host already, for example
*dialout*, *video* or *wheel*. At login pam_otpme puts the user into it
for that session.

Use it for group memberships that only make sense on one host. An OTPme
group reaches every host the user is synced to. A dynamic group stays
where you set it.

You can set dynamic groups on a token, a role, a host and a node. At
login pam_otpme takes the groups of the host and the groups of the login
token. The groups of the roles of that token come with it. A host gives
only its own groups. Its roles add nothing, because the groups of a host
go to every login on it, also to a user who is in none of those roles.

A name that is already an OTPme group is refused. Use that OTPme group
itself instead.

A group that does not exist on the host is skipped. pam_otpme writes a
log message for it.

The host can limit which dynamic groups it takes. In *otpme.conf*:

-   **ALLOW_DYNAMIC_GROUPS = False** turns dynamic groups off on this
    host.

-   **ALLOW_DYNAMIC_GROUPS = wheel, dialout** allows only these two.

-   **DENY_DYNAMIC_GROUPS = wheel** blocks these. It is checked first.

Without these two parameters every dynamic group is used.

The commands are **add_dynamic_group**, **remove_dynamic_group** and
**list_dynamic_groups**. They exist for tokens, roles, hosts and nodes.

## Roles

A role is a group of tokens. Almost everywhere you can use a token, you
can use a role instead. Roles can also be added to other roles, so you
can build them on top of each other.

There are two roles from the start: **REALM_USER** and **SITE_ADMIN**.
The default token of every user is added to REALM_USER. With it the user
can log in to the realm and is a member of the group *realmusers*. A
token in SITE_ADMIN has admin rights for its site.

An example for roles:

-   the role *groupware* gives access to the groupware (CalDAV, CardDAV,
    IMAP)

-   the role *employee* is added to the role *groupware*, so every
    employee has groupware

-   the role *marketing* is added to the role *employee* and to the
    group *marketing*

-   the default token of a marketing user is added to the role
    *marketing*. The user now has groupware access and is in the group
    *marketing*.

If all employees should get a new service later, for example a wiki, you
only add the role *employee* to the access group of the wiki.

## Access Groups

Access groups say who may use a service, and how its sessions work.
Every client gets an access group: a RADIUS client, an LDAP client or an
OIDC client of the SSO portal. For example the access point *ap01* gets
the access group *wlan*. Then you add tokens or roles to the access
group. When a WLAN login arrives, the access group says who is let in.

An access group has more settings, for example how many failed logins
lock a user out (**max_fail**) and after how long the counter is reset
(**max_fail_reset**), see **otpme-accessgroup**(1).

An access group can create a session for its logins. This helps with
services that ask again and again with the same password or OTP, for
example an IMAP server. Note that an OTP is then no longer used only
once: it works as long as the session lives. Per access group you can
set how long a session lives and how many sessions a user may have at
the same time.

An access group can have child access groups. Tokens and roles of the
parent group also have access to the children. When a site is added, the
access group *REALM* gets the children *MGMT* and *LDAP*. So a token
that may log in to the realm can also use the management interface and
LDAP.

The access group *SSO* is different. A token in it may log in to the SSO
portal, but that alone gives no access to the connected applications.
For an application the token must also be in the access group of that
application, for example *nextcloud*.

## File Shares

A file share needs shared storage that is mounted on all nodes, for
example under */otpme-mounts/*. This mount point is the root directory
of the share (**root_dir**). All nodes must see the same storage. We
recommend CephFS or NFS for it.

Add tokens or roles to a share to give them access to it. Clients mount
a share with FUSE, using **otpme-mount**.

By default all nodes serve a share. You can assign single nodes or a
node pool to a share; then only those nodes serve it. The client mounts
the share from one of these nodes, chosen by chance, which spreads the
load.

On the client the share is mounted below the mount root
(**MOUNT_ROOT_DIR**, default */otpme*):

> */otpme/\<user\>/\<realm\>/\<site\>/\<share\>*

A share has an ID, and that is what **otpme-mount** takes:

> *\<realm\>/\<site\>/\<share\>*

The realm is part of it because two realms may have a site of the same
name. You can leave it out and write *\<site\>/\<share\>*; then it is a
share of your own realm.

A **home share** is a special share which gives every user an own
directory. A normal share gives all users the same directory. In a home
share, each user only gets the own directory and sees nothing else.

An example: the home share *home* has the root directory
*/otpme-mounts/home*. When user *alice* mounts it, OTPme creates the
directory

> */otpme-mounts/home/alice*

and hands out this directory as the root of the share. On the computer
of alice it is mounted as

> */otpme/alice/example.org/berlin/home*

The directory belongs to alice, and only alice can read it. Its name is
the user name (*alice*) or the UUID of the user; you choose that when
you create the share.

A root mount token gets */otpme-mounts/home* itself as the root of the
share, so it sees the directories of all users. An encrypted home share
encrypts each directory with an own key, and for that reason it has no
root mount token. See **otpme-share**(1).

A share can be **encrypted**. When it is created, you are asked for a
master password, and the AES key of the share is made from it. The data
is encrypted on the client, so every token that may use the share needs
its own copy of the AES key. This copy is encrypted with the encrypt key
of the user. With **yubikey_piv** this key is on the token, which is why
this token type is the safe way to use encrypted shares. Because each
token needs its own key copy, only tokens can be added to an encrypted
share, not roles.

A directory that is already an encrypted share can be taken over, for
example after a move to another site, or when the share object is gone
and the data is still there. Create the share with **--no-key-gen**, so
OTPme does not make a new key: the data can only be read with the key it
was written with. The settings file in the directory stays as it is, so
the key is still made the same way from the same master password. Then
mount the share once from the login session of root, with a token that
may use the master password of it:

> **otpme-mount --master-password-mount --add-share-key *share*
> mountpoint**

OTPme asks for the master password, makes the key from it and stores it
for your token. After that the share mounts the normal way. See
**otpme-share**(1).

A share can also use SOTP signing. The login to the share must then be
signed with the sign key of the user, see **otpme-share**(1) and
**Tokens** above.

## Node Pools

A node pool is a group of nodes. Assign a pool to a share, and only the
nodes of this pool serve the share.

## Policies

A policy is a rule that OTPme applies to objects. You can add a policy
to units, users, tokens, access groups and other objects. A policy on a
unit applies to the objects in that unit.

**authonaction**  
Ask for a new authentication before an action, for example before a user
is deleted or an ACL is added. You can set how long an authentication
stays valid, and which tokens and roles are exempt.

**autodisable**  
Disable an object after some time, for example **+1h**, **+1D**,
**+1W**, **+1M** or **+1Y**. The time can also count from the last use
of the object instead of the time it was assigned.

**defaultgroups**  
Add new users to the given groups, and set the default group of a user.

**defaultpolicies**  
Add the given policies to new objects of a type.

**defaultroles**  
Add the default token of new users to the given roles.

**defaultunits**  
Say in which unit new objects of a type are created.

**forcetoken**  
Allow only some token types for a login, for example only **fido2** and
**yubikey_piv**. You can also allow only some kinds of credentials, for
example **otp**, **ssh_key**, **smartcard** or **tiqr**. Add this policy
to an access group, a client, a host, a node or a role.

**idrange**  
Set the ranges for the LDAP attributes **uidNumber** and **gidNumber**
that OTPme gives to new users and groups. The numbers can be given in
order or at random.  
Add this policy to a unit or to a site. A new object asks its unit first
and its site second, so a site-wide range is the fallback for every unit
that names none.

**logintimes**  
Allow logins only at certain times, written like a cron entry, for
example only on work days or only during work hours.

**objecttemplates**  
Create new users or hosts from a template, so they start with the
settings of that template.

**password**  
Set what a password or PIN must look like: how long it must be, which
characters it needs, and whether it may be a word from a dictionary.

**tokenacls**  
Give new tokens their ACLs, which say what the user and the creator of a
token may do with it.

# ACCESS CONTROL

OTPme has two kinds of access control:

-   Access groups say who may log in to a service, see **Access Groups**
    above.

-   ACLs say who may see and change objects.

## ACLs (Access Control Lists)

An ACL says what a token or a role may do with an object. Add one with
**add_acl**, for example:

> **otpme-token add_acl *alice/pass* role *helpdesk* edit:password **

Every token in the role *helpdesk* may now change the password of the
token *alice/pass*. Use **list_acls** to see the ACLs of an object and
**del_acl** to remove one.

An ACL has a permission and, after a colon, what it applies to.
**enable:object** for example only allows to enable the object itself,
while **enable** alone allows every enable permission of it
(**enable:object**, **enable:mschap** and so on). A permission that
names one thing is written in the singular (**add:token**), one that
shows a list in the plural (**view:tokens**).

There are three kinds of ACLs. They differ by the **+** in front of
them:

**acl**  
A normal ACL, for example **edit:password**. It applies to the object it
is set on, and only to that object.

**+acl**  
A default ACL, for example **+user:edit** on a unit. It is not used for
the unit itself. It is given to the objects in the unit, as a normal ACL
(without the **+**). So the objects get the ACL, but do not pass it on.

**++acl**  
A recursive default ACL, for example **++user:edit**. Like a default
ACL, but a unit in the unit keeps it as **++acl**. So it goes down
through all units below, and every object there gets it.

An example: with

> **otpme-unit add_acl *hosts* role *helpdesk* ++host:edit **

every host in the unit *hosts* and in all units below it can be changed
by the role *helpdesk*, also the hosts you add later.

A new object gets the default ACLs of its unit when it is created.
Objects that are already there do not, unless you say so: **-a** applies
the default ACLs to the objects of the unit, **-r** also to the objects
in the units below, see **otpme-unit**(1).

An object can refuse inherited ACLs with **disable_acl_inheritance**.
**enable_acl_inheritance** turns it on again.

Which ACLs a kind of object knows is in **otpme-acls**(7). **list_acls**
shows the ACLs an object has, and the shell completion offers the ones
it takes after **add_acl**.

# OFFLINE AUTHENTICATION

When a host can not reach the OTPme server, it can check logins against
data it saved at the last login. This has to be switched on for each
token (**enable_offline**).

At an online login the host saves the token and the session, encrypted.
The key for it comes from the password, the PIN or the answer of the
smartcard of the user (Argon2i).

While the server can not be reached, the host checks logins against this
saved data. It notes which OTPs were used, so an OTP can not be used a
second time.

Two timeouts say how long the saved data may be used: **offline_expiry**
counts from the last online login, **offline_unused_expiry** from the
last use. See **otpme-token**(1).

When the server can be reached again, hostd sends the used OTPs and the
token counters back to it.

# CONFIGURATION MANAGEMENT

OTPme can run configuration jobs on hosts, for example install packages,
add apt repositories, write files or restart services. Jobs are created
with **otpme-deploy**(1).

A job is signed with the sign key of the user who creates it. The
**confd** daemon on each host gets its jobs from the nodes, checks the
signature and runs the job. The result goes back to the nodes.

Two checks must pass before a job runs:

-   The nodes check that the user may create jobs for the host (config
    parameter **allow_confd_jobs**).

-   The host checks that the job is signed by a signer it trusts for
    this job type. The job types are also signer types: **sw_mgmt**,
    **repo_mgmt**, **signer_mgmt**, **service_mgmt**, **file_mgmt** and
    **host_mgmt**. Add them on the host with **otpme-tool add_signer
    --signer-type** *job_type*.

So the nodes decide who may ask, and each host decides what may be done
to it. A node that is taken over can not run jobs on a host without a
valid signature.

Jobs and results are only synced between the nodes of the site. Other
sites do not get them. Package jobs work on Debian and Ubuntu hosts.

confd does not run a job itself. It starts a service of its own for each
job (**otpme-confd-job**). So a long job does not block confd, and a job
that restarts OTPme keeps running and can report its result afterwards.

confd also reports which system and which kernel the host runs, whether
it has to be rebooted, and which packages are installed. You can see and
search this with **otpme-inventory**(1).

# CONFIG PARAMETERS

Config parameters are set on an object with the **config** command.
**show_config** shows them. Set a parameter with:

> **otpme-site config *berlin* *parameter* \[*value*\]**

Remove it again with **-d**:

> **otpme-site config -d *berlin* *parameter***

A parameter is looked up at the object itself, then at its unit, then at
its site. The first value found wins, so a value on a site or unit is
the default for the objects below it. A site can also enforce a
parameter for all of its objects, see **force_site_config_parameters**
below. Above the site nothing is asked: a realm holds no config
parameters. The line *Object types* of each parameter says on which
objects it can be set.

When a site is created, OTPme writes the default of every parameter into
that site. The site keeps these values. Two things follow from that.

A parameter that OTPme got after the site was created is not in
**show_config** of that site, and it has no value there. What an unset
parameter means is up to the code that reads it, so better set it on the
site.

A new default in OTPme does not reach a site that already has the old
value. Set the new value on the site yourself.

Some parameters take a time. The unit is one letter behind the number:

> **s**  
> seconds
>
> **m**  
> minutes
>
> **h**  
> hours
>
> **D**  
> days
>
> **W**  
> weeks
>
> **M**  
> months
>
> **Y**  
> years

> The letters are case sensitive. **m** is minutes and **M** is months,
> and a day is **D**, never **d**. A number without a unit means
> seconds.

The same units are used outside of the config parameters, for example by
**--auto-disable**. A relative time is written with a leading **+**
there, e.g. **+30D**.

A parameter of type **time** is stored as seconds and shown in these
units, in the largest unit that fits. So 86400 is shown as **1D** and
7776000 as **3M**. A parameter of type **int** that takes a time is
shown as the number of seconds.

## General

**confirmation_policy (str, default: paranoid)**  
When OTPme asks before a change. **paranoid** asks for every change, and
for deleting you have to type the name of the object. **normal** only
asks when you delete something, also with the name. **force** never
asks. The option **-f** skips the questions with every policy.  
Object types: site, unit, token

**auto_sign (bool, default: false)**  
Offer to sign the object after each change.  
On an object a token can be assigned to — a role, a group, an access
group, a host or a node — it says to sign the token for that assignment,
which is what **add_token --sign** does by hand. A host can be told to
let an SSH key in only with such a signature, see **otpme-role**(1).  
Object types: site, unit, user, token, script, role, group, accessgroup,
host, node

**auto_revoke (bool, default: true)**  
Revoke the signatures of an object when it is changed.  
Object types: site, unit, user, token, script

**force_site_config_parameters (list)**  
Config parameters that the site enforces for all of its objects. For a
parameter in this list the value of the site wins. The values on the
objects below it (units, users, tokens and so on) are not used at all.  
If the site has no value for such a parameter, the values below are
ignored as well, and the default of the parameter applies.  
Only parameters that are valid for a site can be enforced, and this
parameter can not enforce itself. Add more values with **-a**, remove
single ones with **-d**.  
Object types: site

**changelog (bool, default: true)**  
Write the commands that change this object into its changelog. Looked up
at the object, then at its unit, then at its site. Switch it off for
objects that change very often. A site that wants its own setting
everywhere adds **changelog** to **force_site_config_parameters**.  
Object types: all tree objects (site, unit, user, token, ...), but not
the realm

**allow_changelog_clearing (bool, default: true)**  
Allow **clear_changelog** on this object. Switch it off to keep the
changelog of an object complete.  
Object types: all tree objects (site, unit, user, token, ...), but not
the realm

**ldap_verify_acls (bool, default: true)**  
Whether **otpme-ldapd** checks the ACLs of the objects it hands out.
With the check, an attribute only goes to a token that holds the ACL
**view:attribute:***attr* on the object, or that is in
**ldif_whitelist_attributes**. Switch it off to let a token read every
attribute of every object it can find, for example for a service account
that syncs the directory.  
The value is looked up at the token that asks, then at its user, its
unit and its site. So you can switch it off for one token without
opening the whole site. For admin tokens the ACLs are never checked.  
Can only be changed by an admin.  
Object types: site, unit, user, token

**ldap_on_request_attributes (list)**  
LDIF attributes that **otpme-ldapd** only returns when the search asks
for them by name. A search that asks for all attributes gets everything
but these. Unset means nothing is held back.  
This keeps big attributes out of searches that do not need them. A
client that asks for all attributes in every search (SOGo does that in
every address book search) would otherwise pull the photo of every hit
over the network. Set **jpegPhoto** here to stop that. A search with
"\*" asks for all user attributes. **RFC 4511** (4.5.1.8) does not
promise that a server returns all of them: it tells client implementors
that attributes can be missing "due to access controls or other
restrictions". So a client has to cope with it.  
The value is looked up at the token that asks, then at its user, its
unit and its site. A client that really needs these attributes in every
search can get an empty list on its token. Upper and lower case in
attribute names does not matter. Add more values with **-a**, remove
single ones with **-d**.  
Object types: site, unit, user, token

**ldif_whitelist_attributes (list, default: dn, objectClass, uid, cn, displayName, entryUUID, l, mail, mailLocalAddress)**  
LDIF attributes that are handed out without the ACL
**view:attribute:***attr*. Every other attribute only goes to a token
that holds this ACL on the object.  
A value on the token that asks wins, so one token can see more or less
than the rest of the site. Without such a value the list comes from the
site that answers the LDAP request (see **otpme-ldapd**), not from the
site of the object, and it applies to all objects of that site.  
The default is what an LDAP client needs to find an object at all. Make
it shorter to hide the mail address, for example, or longer to show more
attributes to every user that is logged in. Add more values with **-a**,
remove single ones with **-d**.  
Can only be changed by an admin.  
Object types: site, token

**allow_non_admin_trash_empty (bool, default: true)**  
Whether tokens that are no admin may run **otpme-trash empty**. If they
may, they only empty the trash entries of their own token. If they may
not, only admins can empty the trash. The value is looked up at the
token that asks, then at its user, its unit and its site.  
Object types: site, unit, user, token

## Key Backup

**private_key_backup_key (str)**  
The public RSA key (base64) that the private keys of users are encrypted
with for the backup. When a YubiKey PIV token is deployed below this
object, the backup of its keys is encrypted with this key (**--backup**
and **--restore-from-server**, see **otpme-token**(1)). Whoever has the
private part of this key can decrypt the backups of all these tokens.  
If the parameter has no value, OTPme creates a key pair when you set it.
This happens on the computer where you run the command: only the public
key goes to OTPme, the private key is written to a file you choose
(*/dev/shm/\<name\>.pem* by default). Keep this file in a safe place
outside of OTPme, for example on an encrypted medium in a safe. Without
it the key backups of the tokens can not be restored.  
Can only be changed by an admin.  
Object types: site, unit

**private_key_backup_key_len (int, default: 4096)**  
How long the key from **private_key_backup_key** is, in bits. Allowed:
2048, 3072 and 4096.  
Object types: site, unit

## Password Hashing

**default_pw_hash_type (str, default: Argon2_i)**  
Which hash new password tokens use. Possible values: **Argon2_i**,
**Argon2_d**, **Argon2_id**, **PBKDF2** and **HKDF**. The settings of
each hash are further down, see **Hash Parameters**.  
Object types: site, unit, user, token

**session_hash_type (str, default: Argon2_i)**  
Which hash is used for session passwords. Same values as
**default_pw_hash_type**.  
Object types: site, unit, user, token

## User Scripts

Every user has scripts for a few tasks. These parameters say which
script a new user gets. The scripts themselves are managed with
**otpme-script**(1).

Before a script runs, OTPme checks its signatures against the signers of
that script type on this host or node (**otpme-tool add_signer
--signer-type** *script_type*). This only happens when there is such a
signer. Without one the script runs unchecked.

**How a script gets its values**

OTPme has a set of values for each script, for example the user and the
token of a login. The script options say how the script gets them. Set
the options together with the script, for example with **otpme-user
auth_script** *user* *script* **--** *options*, see **otpme-user**(1).
There are three forms:

> **\[***NAME***\]**  
> The value goes into the environment of the script, under this name.
>
> **%***name*  
> The value becomes a command line argument (**$1**, **$2**, ... in the
> order of the options).
>
> *anything else*  
> goes to the command line as it is.

Without any options the script gets every value in its environment,
under the name of the value in small letters (**auth_user** and so on).
A value that is not set is left out.

An example:

> **otpme-user auth_script *alice* *scripts/auth_script.sh* --
> \[AUTH_USER\] %auth_client -v**

The script then has **AUTH_USER** in its environment, gets the client as
**$1** and **-v** as **$2**. A value that is not set becomes an empty
argument here.

**The values of an auth script**

**auth_type**, **auth_user**, **auth_token**, **auth_group**,
**auth_client**, **auth_client_ip**, **auth_pass**, **auth_otp**,
**auth_challenge**, **auth_response** and **auth_nt_key**. Which of them
have a value depends on the kind of login: **auth_pass** with a
password, **auth_otp** with a one-time password, and the challenge and
response values with MSCHAP and SSH.

The script allows the login with exit code 0 and denies it with every
other code. For an MSCHAP login it also has to write **NT_KEY: ***key*
to stdout.

**default_key_script (str, default: scripts/key_script.sh)**  
Works with the private keys of the user: signing, decrypting and
changing the key password. With a **yubikey_piv** token it talks to the
YubiKey instead of a stored key.  
Object types: site, unit

**default_auth_script (str, default: scripts/auth_script.sh)**  
Runs on the node during a login. It gets the kind of login, the user,
the access group, the token and the client, and can allow or deny the
login. Use it for checks of your own.  
Object types: site, unit

**default_agent_script (str, default: scripts/agent_script.sh)**  
Starts the agent of the user at the login through PAM, for example
ssh-agent or gpg-agent, with the right options.  
Object types: site, unit

**default_login_script (str, default: scripts/login_script.sh)**  
Runs on the host at the login through PAM, so you can do things there.  
Object types: site, unit

**run_foreign_user_auth_scripts (bool, default: false)**  
If enabled, a login of a user of another site may run the auth scripts
of that user.  
The auth script of a user, and the auth script of their token, are
scripts of the site of that user. Running one means running code of that
site here, on your node, at every login of that user.  
Off by default. The login then goes on without these scripts. The auth
scripts of your own users always run.  
Object types: site

## User Management

**user_photo_dimensions (str, default: 300x450)**  
How big the photo of a user is, as *width***x***height* in pixels. Each
side must be between 16 and 4096.  
A photo of another size is not taken as it is: OTPme asks whether to
resize it, and refuses it if you say no. **-f** resizes without asking,
and the profile page of the SSO portal asks in the browser.  
Resizing makes the photo big enough to cover the size and cuts off the
rest around the middle. So a photo with another ratio of width and
height loses the same amount on both sides instead of looking squeezed.
The EXIF orientation of the photo is used. Photos that are already
stored stay as they are.  
The value is looked up at the user, then at the unit, then at the
site.  
Object types: site, unit, user

**failed_pass_history (int, default: 16)**  
How many wrong passwords OTPme remembers per user. The same wrong
password again is not counted as a new failure, so a client that repeats
an old password does not lock the user out. The locking itself is done
by the access group, see **max_fail** in **otpme-accessgroup**(1).  
Object types: site, unit, user

**add_default_token (bool, default: true)**  
Create a default token for every new user.  
Object types: site, unit

**default_token_name (str, default: login)**  
The name of this default token.  
Object types: site, unit

**default_token_type (str, default: hotp)**  
The type of this default token. Every token type of OTPme can be used,
see **Tokens** above.  
Object types: site, unit

**default_sso_token_name (str, default: sso-\<realm\>-\<site\>)**  
The name of the token that the SSO portal deploys, recovers and gives
the role of the default token to. It must be another name than
**default_token_name**.  
The parameter belongs to the site, and OTPme reads it from the site of
the portal the user is using, not from the site of the user. So a user
of one site who logs in at the portal of another site gets the name of
that portal.  
Two sites with two names are what lets one hardware security key work
for both. Each site then has its own OTPme token, and each token its own
WebAuthn credential for the RP ID of that portal. The default name
already contains realm and site, so two sites never get the same name by
accident.  
This parameter does not create the token. An admin adds it and puts it
into the roles of that site.  
Object types: site

**user_key_len (int, default: 3072)**  
How long the RSA keys of a user are, in bits. Allowed: 2048, 3072, 4096
and 8192. With a **yubikey_piv** token the keys are made on the token
instead, see **--key-len** in **otpme-token**(1).  
Object types: site, unit, user

**allow_default_token_rename (bool, default: false)**  
If enabled, users are allowed to rename their default token.  
Object types: site, unit, user

**allow_default_token_deletion (bool, default: false)**  
If enabled, users are allowed to delete their default token.  
Object types: site, unit, user

**allow_temp_passwords (bool, default: false)**  
Allow a temporary password on a token (**otpme-token temp_password**).
The token then also works with this password, for one hour by default
(**--duration**), and after that only with its own credentials again.  
This is for an admin or the IT support, to work as the user for a while,
for example to set up a notebook for that user. The SSO portal can do
the same, see **admin_access_role**. See **otpme-token**(1).  
Object types: site, unit, user, token

**allow_sso_account_recovery (bool, default: false)**  
The main switch of the token recovery in the SSO portal, the link
**Can't sign in?** on the login page (see
**allow_sso_token_recovery**).  
With it off, asking for a recovery mail gets the same answer as asking
for a user that does not exist, so nobody learns whether an account is
there. A recovery link that somebody still has is refused.  
This switch says whether recovery is offered at all,
**allow_sso_token_recovery** says which token types it may hand out.
Whether the login page shows the link to it is
**sso_show_recover_link**.  
The value is looked up at the user, then at the unit, then at the site,
on the home site of the user.  
Object types: site, unit, user

**allow_sso_token_recovery (list, default: empty)**  
The token types a user may get back through the SSO portal. A user who
lost the token asks for a mail, and the mail holds a link to deploy the
token again.  
This always works on the SSO token of the user, the one named by
**default_sso_token_name**. If the type of that token is not in this
list, recovery is refused. The default is an empty list, so recovery is
off.  
The mail address for it is kept on the user, in the LDAP attribute
**otpmeRecoveryMail**. The value is looked up at the user, then at the
unit, then at the site, on the home site of the user.  
Object types: site, unit, user

**sso_recovery_link_ttl (int, default: 900)**  
How long a recovery link from the mail works, in seconds. Time units are
allowed, for example **15m** or **2h**. It must be between one minute
and 24 hours: a typo like **1** (one second) fails at once, and nobody
opens a recovery window of days by accident.  
The value is looked up at the user, then at the unit, then at the site,
on the home site of the user.  
Object types: site, unit, user

**sso_recovery_mail_from (str)**  
The sender of the recovery mail, used as envelope sender and as
**From:**. The home site of the user sends the mail, over the
**smtp_relay\_\*** parameters. There is no default: without a sender no
mail is sent, and recovery does not work.  
The text of the mail is the info text of the **SSO** access group of
that site, one text per language (**otpme-accessgroup info --language**,
see **otpme-accessgroup**(1)). A text written without a language is the
note of the admin and is never sent.  
The first line of the text is the subject, then comes an empty line,
then the body. **{user_name}**, **{minutes}** and **{reset_url}** are
filled in.  
A new site gets the English text that OTPme brings with it. If the
access group has no text for the language of the user, OTPme uses the
English one, and if that is missing too, the text it brings with it,
translated into the language of the user. The language is the one of the
user (**otpme-user language**), or the one the browser asked for when
the user has none.  
Object types: site, unit, user

**admin_access_role (str)**  
The SSO portal has an admin access: a member of this role can set a
temporary password on the token of another user there. The admin or the
IT support can then work as this user for a while, for example to set up
a notebook (see **allow_temp_passwords**).  
The value is looked up at the token, then at the user, then at the unit,
then at the site. For a user of another site this only happens when the
local site trusts that site, see **admin_access_trusts**. Without that
trust only the value of the local site itself is used.  
Can only be changed by an admin.  
Object types: site, unit, user, token

**admin_access_trusts (list)**  
The sites this site trusts for **admin_access_role**. When a user of one
of these sites opens an admin access here, OTPme uses the role from the
user of that site. For every other site only the **admin_access_role**
of this site is used. Users of the own site are always trusted.  
Object types: site

**password_allowed_chars (str, default: 0-9A-Za-z!@#$%&\*()\_+-={}\[\]:;\<\>.?/)**  
Which characters a password may have. Ranges like **0-9** are allowed.
The password policy checks this, see **otpme-policy**(1).  
Object types: site, unit, user

## Certificates

Every site has its own CA. It issues the certificates of the nodes and
hosts of the site, and the certificate of the site itself, which is used
for TLS and for RADIUS. The CA of a site is signed by the CA of the
realm, the CA of a sub-site by the CA of its parent site.

**cert_key_len (int, default: 3072)**  
How long the RSA key of a new certificate is, in bits. Allowed: 2048,
3072, 4096 and 8192.  
Object types: site, unit, ca

**cert_sign_algo (str, default: sha256)**  
The hash a certificate is signed with. Allowed: **sha256**, **sha384**
and **sha512**.  
Object types: site, unit, ca

**crl_sign_algo (str, default: sha256)**  
The hash a certificate revocation list (CRL) is signed with. Same values
as **cert_sign_algo**.  
Object types: site, unit, ca

## File Shares

**default_share_add_script (str, default: scripts/add_share.sh)**  
The script a new share gets as its add script. It runs once, when the
share is created, and sets up the directories of the share.  
Object types: site, unit

**default_share_mount_script (str, default: scripts/mount_share.sh)**  
The script a new share gets as its mount script. It runs every time a
user mounts the share. Use it to mount the storage behind the share at
the first access, for example an NFS or CephFS backend.  
Both scripts are run by scriptd as **ROOT_SCRIPT_USER** and
**ROOT_SCRIPT_GROUP** (**nobody** and **nogroup** by default, see
**otpme.conf**(5)), never as root and never as the OTPme user. So a
script that has to mount something or write outside its own directories
needs **sudo** for these commands. See **otpme-share**(1).  
Object types: site, unit

**share_root (str, default: /otpme-mounts/)**  
The directory that holds the shares of this site. A new share gets
*share_root***/***share name* as its own directory, so with the default
a share named *projects* gets */otpme-mounts/projects*.  
It is also the boundary for the directory of a share: a share can only
have a directory below **share_root**. That is why only an admin can
change this parameter, and not everybody who may edit a share.  
The directory must exist when you set the parameter. **SHARE_ROOT** in
**otpme.conf**(5) wins over it on a single host.  
Can only be changed by an admin.  
Object types: site, unit

## Hosts

**allow_confd_jobs (list)**  
Tokens and roles that may create configuration jobs for a host (see
**otpme-deploy**(1)). Give them as a comma separated list of OIDs, for
example **role\|example.org/berlin/deploy-admins** or
**token\|example.org/berlin/alice/login**. A token counts if it is in
one of the roles, also through nested roles. The OIDs are stored as
UUIDs, so renaming a role or token keeps the permission.  
The value is looked up for each target host; the most specific match
wins (host or node overrides unit overrides site). So a role can be
allowed for the hosts of one unit only. Unset (default) means nobody may
create jobs.  
This only decides who may create a job. The host still checks the job
signature against its own signers.  
Object types: site, unit, host, node

**conf_job_max_age (time, default: 3M, i.e. 90 days)**  
How long configuration jobs and their results are kept on the nodes. It
takes time units, e.g. **180D**. The lowest value is one day. Jobs that
worked are kept too, so you can see which jobs were already sent. A job
that failed on a host is kept until it is acknowledged with
**otpme-deploy ack**, unless it was taken back with **otpme-deploy
cancel** — that answers it as well. The **confd** daemon on the master
node removes old jobs once an hour.  
A remote access job goes by **remote_access_job_max_age** instead.  
Object types: site

**remote_access_job_max_age (time, default: 1h)**  
How long a remote access job is kept after it expired. It takes time
units, e.g. **30m**, and **0** means as soon as it expires.  
Its own value, because such a job is a different kind of record:
**otpme-shell** makes one for every shell, it is good for five minutes,
and it says nothing afterwards — whoever asked for the shell stood there
while it happened. Kept as long as every other job they would pile up
for three months.  
Counted from the expiry and not from the creation, because that is when
the job stopped being of use to anybody.  
Object types: site

**hosts_accessgroup (str)**  
The access group that every new host is added to. The value is the name
of an access group that exists.  
This is for MAC Authentication Bypass (MAB): a device that can not log
in by itself, for example a printer, is let into the network by its MAC
address. The switch asks OTPme with that address, and the access group
of the host says whether it is let in.  
You need the **add:host** ACL on that access group to set this
parameter, because the hosts are added to it later without another
check.  
Object types: site, unit

**hosts_role (str)**  
The role that every new host is added to. The value is the name of a
role that exists, and it must be a role of the same site. You can also
write it as *site***/***role*, which is how a role is shown.  
You need the **add:host** ACL on that role to set this parameter,
because the hosts are added to it later without another check.  
Object types: site, unit

## Devices

A device is network equipment that can not log in by itself, for example
an IP phone or a printer. It only has a MAC address and is let into the
network with MAC Authentication Bypass (MAB), see **otpme-device**(1). A
host is more than that: it has joined the realm and runs hostd. A host
can have a MAC address too, so it can also be used for MAB.

**devices_accessgroup (str)**  
The access group that every new device is added to. The value is the
name of an access group that exists. The switch asks OTPme with the MAC
address of the device, and this access group says whether it is let
in.  
You need the **add:device** ACL on that access group to set this
parameter, because the devices are added to it later without another
check.  
Object types: site, unit

**devices_role (str)**  
The role that every new device is added to. The value is the name of a
role that exists, and it must be a role of the same site. You can also
write it as *site***/***role*, which is how a role is shown.  
You need the **add:device** ACL on that role to set this parameter,
because the devices are added to it later without another check.  
Object types: site, unit

## VLAN

**vlans (list)**  
The VLANs that a port gets after an 802.1X or MAB login. Each value is
the name of a VLAN object, see **otpme-vlan**(1).  
This is the second of the two ways to assign a VLAN, and the one that is
asked last. A VLAN of the site that answers the RADIUS request can name
the object itself, or a role the object is in, and such a membership
wins over this parameter every time. Only where no VLAN of that site
names the object is this parameter looked at, see **otpme-vlan**(1).  
The value is looked up at the token, then at the user, then at the host
or device, then at the unit, then at the site. The first one found wins,
so a VLAN on a token beats the one on the user or the site.  
To assign a VLAN you need the **assign** ACL on the VLAN object. So you
can give somebody the right to hand out one VLAN, and no other.  
A VLAN of another site is written as *site***/***vlan*. This is needed
when all users live on the master site while each site has its own
VLANs. Whether such an assignment counts is decided by the site that
answers the RADIUS request, through its **vlan_trusts**.  
Assign at most one VLAN per site. The site that answers the RADIUS
request returns its own VLAN. If none of the VLANs belongs to it, it
returns the first one its **vlan_trusts** allow, in the order of those
entries. Without a matching entry it returns no VLAN at all.  
What the switch gets as **Tunnel-Private-Group-Id** is the VLAN ID of
the VLAN object, or its name if it has no VLAN ID. The assignment is
stored by UUID, so a VLAN can be renamed without losing it.  
Object types: site, unit, host, device, user, token

**vlan_trusts (list)**  
Which VLAN assignments this site accepts when it answers a RADIUS
request. The port belongs to the network of this site, whoever owns the
VLAN object, so this site decides. This parameter is the only place
where that is decided. Without a matching entry the assignment is
ignored.  
An entry is needed as soon as the object or the VLAN belongs to another
site. Only an own VLAN for an own object works without one.  
An entry looks like *site*\[**:***vlan_site*\[**/***vlan*\]\]. *site* is
the site of the object the VLAN is assigned to, *vlan_site***/***vlan*
is the VLAN itself. What you leave out means "all".  
So the entries on site *berlin* mean:

**munich**  
allows all VLANs for objects of site munich

**munich:berlin**  
allows all VLANs of site berlin for objects of site munich

**munich:berlin/home**  
allows the VLAN *berlin/home* for objects of site munich

**munich:munich/clients**  
allows the VLAN *munich/clients* for objects of site munich, which
berlin then switches in its own network

**berlin:munich/clients**  
allows the VLAN *munich/clients* for objects of site berlin itself

If an object has VLANs of several sites, the VLAN of this site wins;
after that the order of the entries decides.  
The **assign** ACL on the VLAN object is no replacement for an entry: it
is checked by the site that makes the assignment, against its own copy
of the VLAN, so it says nothing about what this site allows. See
**otpme-vlan**(1).  
Object types: site

## SSO Portal

**device_token_roles (list)**  
Comma separated list of roles the SSO portal adds device tokens to. A
value is a role of the current site, or *site***/***role* for a role of
another site. The value is looked up on the user, then on the user's
unit and the units above it, then on the site. The first one found
wins.  
The role's info text is shown in the portal settings, in the language of
whoever is looking (**otpme-role info --language**). The text written
without a language is the administrator's own note and is never shown.  
One list serves every portal the user signs in at. A portal only offers
roles of its own site, so each one shows its own part of the list. A
role of another site is therefore not a mistake. It is what the user
gets at that site's portal, if that portal allows it via
**device_token_roles_trusts**.  
Object types: site, unit, user

**device_token_roles_trusts (list)**  
Which of this site's roles the SSO portal offers to users of other
sites. Naming a role in the user's **device_token_roles** is the home
site's half of the decision, this parameter is the portal's half. This
parameter is the only place where that is decided. Users of this site
need no entry.  
An entry is *site* or *site***:***role*. *site* is the home site of the
user, *role* is a role of *this* site. No other role is ever offered
here. Both kinds of entry are needed.  
So the entries on site *munich* mean:

**berlin**  
allows device tokens here at all for users of site berlin

**berlin:wlan-users**  
allows this site's role *wlan-users* for users of site berlin, if their
own **device_token_roles** names it

Without the bare site entry a user of that site is offered nothing here.
A role without its own entry is left out, even when the user's
**device_token_roles** names it.  
Object types: site

**device_token_suffix (str)**  
Makes a role usable for SSO device tokens. A role without this parameter
is not shown in the SSO portal at all, so it works as the opt-in switch
for **device_token_roles**.  
The value is appended to the token name when the portal registers a
device token under this role, with a **-** in between: the device
**iphone** under a role whose suffix is **wlan** becomes the token
**iphone-wlan**. So the suffix is written without a leading dash.  
It is what tells two tokens of the same device apart where a user is in
more than one of the **device_token_roles** — **iphone-wlan** and
**iphone-vpn**.  
Object types: role

**device_token_types (list)**  
Comma-separated list of the token types the SSO portal creates for this
role's device tokens: **password** and/or **totp**. With more than one
the user chooses per token, and the first one is the default. Unset
means **password**.  
A **totp** device token is created with its PIN disabled, because the
device has to produce the OTP on its own. Its secret is shown once when
it is created, with a QR code for an authenticator app.  
Object types: role

**max_device_tokens (int)**  
How many device tokens one user may hold in this role, between 1
and 128. Unset means no limit. Once the limit is reached the SSO portal
shows no form to add another one, and adding one is refused.  
Object types: role

**device_token_mschap (bool, default: false)**  
Whether a **password** device token the SSO portal creates for this role
gets MSCHAP enabled, e.g. for WLAN with PEAP/MSCHAPv2. It is off unless
the role says so, because MSCHAP keeps the NT hash of the password on
the server. It only affects tokens created from then on. A **totp**
device token is always created without MSCHAP.  
Object types: role

**sso_allow_session_mgmt (bool, default: false)**  
Whether a user may see and end their own sessions on the Settings page
of the SSO portal. It is off by default, because the listing shows where
the account is logged in: client or host, address, token and times. That
is something an install should hand out deliberately.  
Only the sessions of the portal's own site are listed, because that is
where a login of this portal lives. Ending a session also ends its child
sessions and the application (OIDC) sessions below it. The session the
Settings page itself runs in is shown, but it cannot be ended there.  
Object types: site, unit, user

**sso_profile_attributes (list, default: uid,givenName,sn,mail,telephoneNumber,mobile,title,o,ou,departmentNumber,l,createTimestamp,modifyTimestamp)**  
Comma-separated list of the LDAP attributes the Profile page of the SSO
portal shows, in this order. The page is reached by clicking the user
name in the navigation bar. It shows the photo, and of these attributes
the ones the user has.  
What is there for the machines rather than for the user is left out by
default: **uidNumber**, **gidNumber**, **homeDirectory**,
**loginShell**, **entryUUID**, and **cn** and **displayName**, which are
built from the others.  
The page is answered by the user's home site, so the value is looked up
there: first on the user, then on the user's unit and the units above
it, then on the site. The first one found wins.  
Object types: site, unit, user

**sso_allow_profile_edit (list)**  
Comma-separated list of the LDAP attributes a user may change on the
Profile page of the SSO portal, e.g. **mail,telephoneNumber,mobile**.
**jpegPhoto** allows setting and removing the photo. Unset (the default)
means nothing can be changed there.  
An attribute listed here is shown on the page even when
**sso_profile_attributes** leaves it out, after the ones listed there.
Attributes the user's extensions keep read-only, like **uid**, cannot be
changed even when they are listed.  
The change is made on the user's home site, so the value is looked up
there: first on the user, then on the user's unit and the units above
it, then on the site. The first one found wins. Whether a change needs a
fresh authentication is **sso_profile_edit_reauth**.  
One change may carry up to 16 values of 1024 characters each. A photo
must be a JPEG of at most 8 MiB, and of at most 512 KiB once it has been
resized to **user_photo_dimensions**. A photo of another size is only
stored after the user agreed to have it resized.  
Object types: site, unit, user

**sso_allow_passkeys (bool, default: true)**  
Whether passkeys (FIDO2 resident credentials) are accepted as a login
method on this site. Set it to false to refuse passkey logins
completely. The login mask of the SSO portal stays the same.  
It resolves fail-open: only an explicit false blocks.  
A user of another site only gets the Settings card when this site lists
the user's home site under **sso_allow_passkeys_trusts**. There is no
fallback to this site's own setting. The card also needs
**sso_allow_passkey_mgmt**.  
Object types: site, unit, user

**sso_allow_passkey_mgmt (bool, default: false)**  
Whether a user may manage their own passkeys on the Settings page of the
SSO portal: listing, registering, enabling and disabling, deleting. It
only works on top of **sso_allow_passkeys**, which still has to allow
passkeys.  
It is off by default, because which credentials a user may add or remove
on their own is something an install should hand out deliberately.
Signing in with a passkey is not affected.  
Object types: site, unit, user

**sso_allow_passkeys_trusts (list)**  
Comma-separated list of sites this site trusts with passkeys of users of
other sites. It has to be set on **both** sites. Each of them makes a
decision of its own, and each can only read its own list, because the
parameter is not synced to other sites.

-   On the site whose SSO portal the user stands in front of, it lists
    the home sites of the users. This protects the portal site's backend
    and access groups from users of other sites. A passkey registered
    here is written into this site's backend and added to this site's
    SSO access group, roles and groups. So it gives a user of another
    site a new way in here. Without an entry the Settings card is not
    offered: listing, registering, enabling and disabling passkeys.

-   On the user's home site, it lists the portal sites. This protects
    the users of the home site from other sites. The portal site runs
    the registration and decides which authenticator is bound to the
    account, so whoever controls that site could bind one of their own.
    The home site only accepts such a request from a site in its list.
    It tells the requesting site by the certificate of its node, not by
    anything the request says.

Neither side can make the other's decision. The home site protects its
users from other sites, the portal site protects its backend and access
groups from users of other sites. A site not in the list gets nothing.
There is no fallback to the local **sso_allow_passkeys**. Users of this
site need no entry.  
Object types: site

**sso_allow_fido2_deploy (bool, default: true)**  
Whether FIDO2 may be chosen when the portal hands a user a new SSO
token. That happens on the deploy page of a first login, and for the new
token of a token recovery. Set it to false to leave FIDO2 to the
administrator.  
It does not say whether a recovery runs at all. That is decided by
**allow_sso_account_recovery** and **allow_sso_token_recovery**, which
look at the token the user already has.  
Registering further keys on the Settings page is decided by
**sso_allow_fido2**, which this parameter narrows.  
Object types: site, unit, user, token

**force_fido2_rp (str, default: realm)**  
Which Relying Party ID a FIDO2 token is registered for. **realm** uses
the realm name, **sso_fqdn** uses the SSO FQDN of the site. It only
applies to FIDO2 tokens; a passkey always uses the SSO FQDN of the
site.  
The RP ID is written to the token when it is registered, and the login
takes it from there. So a change only applies to keys registered from
then on, and keys already registered keep working.  
A browser only hands out a credential when the RP ID matches the page it
is on: it has to be the FQDN of the page or a domain above it. So
**realm** only works when the FQDN of the portal is below the realm
name. **sso_fqdn** always matches the portal of its own site.  
This does not make one token work at several portals. Every site has its
own SSO token, see **default_sso_token_name**.  
Valid values: **realm**, **sso_fqdn**.  
Object types: site, unit, user

**fido2_decoy_cred_id_len (int, default: 64)**  
Length in bytes of the decoy credential IDs the FIDO2 login hands out
when the user is unknown or has no security key. The decoys are there so
that the answer looks the same either way.  
All a browser gets to see is the credential ID and how many of them
there are. So a length that no authenticator in your realm produces
gives the decoy away in a single request. 64 is what a YubiKey hands
out. Allowed values are 16 to 1023.  
Object types: site

**fido2_decoy_max_creds (int, default: 2)**  
How many decoy credentials are handed out at most. The number is derived
from the user name, so it is the same on every attempt, and it is spread
over 1 to this value.  
A fixed count of one would give away every user who has a second
security key, by the length of the list alone. Set it to the largest
number of security keys your users really carry. 1 switches the
variation off. The lowest value is 1; there is no upper limit.  
Object types: site

**sso_allow_totp_deploy (bool, default: true)**  
Whether TOTP may be chosen when the portal hands a user a new SSO token.
That happens on the deploy page of a first login, and for the new token
of a token recovery. Set it to false to leave TOTP to the
administrator.  
It does not say whether a recovery runs at all. That is decided by
**allow_sso_account_recovery** and **allow_sso_token_recovery**, which
look at the token the user already has.  
Adding further authenticator apps on the Settings page is decided by
**sso_allow_totp**, which this parameter narrows.  
Object types: site, unit, user, token

**sso_allow_totp (bool, default: true)**  
Whether TOTP tokens may be used in the SSO portal at all. That covers
signing in with the PIN followed by the code of an authenticator app,
and managing authenticator apps on the Settings page. Managing them also
needs **sso_allow_totp_mgmt**.  
Set it to false to refuse TOTP logins to the portal and to hide the
card. It takes **sso_allow_totp_deploy** with it. Other access groups
are not affected.  
It is checked after the token was verified, so a code sent with a
refused token is spent all the same. For a user of another site both the
user's own value and this site have to allow it.  
It resolves fail-open: only an explicit false blocks. So adding the
parameter underneath a running installation cannot switch off a login
that works today.  
A user of another site gets the Settings card only when this site lists
the user's home site under **sso_allow_totp_trusts**.  
Object types: site, unit, user

**sso_allow_totp_mgmt (bool, default: false)**  
Whether a user may manage their own authenticator apps on the Settings
page of the SSO portal: listing, adding, enabling and disabling,
deleting, making one the default token, and setting a new PIN on one. It
only works on top of **sso_allow_totp**, which still has to allow
TOTP.  
It is off by default, because which credentials a user may add or remove
on their own is something an install should hand out deliberately.
Signing in with a TOTP token is not affected.  
Making one the default token also needs the current default token to be
one the portal manages: FIDO2, tiqr or TOTP, each with its own
**sso_allow\_\*\_mgmt** on. A default token the administrator chose is
never replaced or renamed from the Settings page.  
With it off the administrator manages the tokens of the user. The
Settings page then offers one thing instead: changing the PIN of the OTP
token the user signed in with, and it asks for the current PIN. With it
on that form is gone, and PINs are set on the authenticator apps in the
card.  
Setting a new PIN on an authenticator app asks for no current PIN. The
proof is the fresh authentication of **deploy_totp_token_reauth**, so a
user who forgot the PIN can set a new one. The secret stays, so the app
keeps working.  
Object types: site, unit, user

**sso_allow_totp_trusts (list)**  
Comma-separated list of sites this site trusts with authenticator apps
(TOTP tokens) of users of other sites. It has to be set on **both**
sites. Each of them makes a decision of its own, and each can only read
its own list, because the parameter is not synced to other sites.

-   On the site whose SSO portal the user stands in front of, it lists
    the home sites of the users. This protects the portal site's backend
    and access groups from users of other sites. A token added here is
    written into this site's backend and added to this site's SSO access
    group, roles and groups. So it gives a user of another site a new
    way in here. Without an entry the Settings card is not offered:
    listing, adding, enabling and disabling authenticator apps.

-   On the user's home site, it lists the portal sites. This protects
    the secrets of the home site's users from other sites. The secret
    and the PIN of a new authenticator app are made on the home site,
    but they are shown by the portal site, so whoever controls that site
    can capture them and sign in as the user. The home site only accepts
    such a request from a site in its list. It tells the requesting site
    by the certificate of its node, not by anything the request says.

Neither side can make the other's decision. The home site protects the
secrets of its users, the portal site protects its backend and access
groups from users of other sites. A site not in the list gets nothing.
There is no fallback to the local **sso_allow_totp**. Users of this site
need no entry.  
Without the trust the Settings card is not offered at all, so an
authenticator app cannot be deleted there either. Signing in with one is
not affected.  
Object types: site

**sso_allow_password_deploy (bool, default: false)**  
Whether a password may be chosen when the portal hands a user a new SSO
token. That happens on the deploy page of a first login, and for the new
token of a token recovery.  
It is off by default, because a password is a weaker credential than
TOTP or a security key. An install has to decide for it.  
It does not say whether a recovery runs at all. That is decided by
**allow_sso_account_recovery** and **allow_sso_token_recovery**, which
look at the token the user already has.  
Object types: site, unit, user, token

**sso_allow_tiqr_deploy (bool, default: false)**  
Whether tiqr may be chosen when the portal hands a user a new SSO token.
That happens on the deploy page of a first login, and for the new token
of a token recovery.  
It is off by default, because tiqr needs a **tiqr_secret** on the site
and the tiqr app on a phone. So it should be a deliberate choice, not a
button that appears on every install.  
It does not say whether a recovery runs at all. That is decided by
**allow_sso_account_recovery** and **allow_sso_token_recovery**, which
look at the token the user already has.  
Enrolling further phones on the Settings page is decided by
**sso_allow_tiqr**, which this parameter narrows. A type nobody may sign
in with is not one to hand somebody as their new token.  
Object types: site, unit, user, token

**sso_allow_tiqr (bool, default: true)**  
Whether tiqr may be used in the SSO portal at all. That covers signing
in by confirming on a phone, and managing phones on the Settings page,
enrolling one included. Managing them also needs
**sso_allow_tiqr_mgmt**.  
Set it to false to refuse tiqr logins completely and to hide the card.  
It resolves fail-open: only an explicit false blocks. So adding the
parameter underneath a running installation cannot switch off a login
that works today.  
This one defaults to *true*, while **sso_allow_tiqr_deploy** defaults to
*false*. That is what keeps tiqr out of the way on an installation that
never set it up: a tiqr login needs a phone somebody enrolled
deliberately.  
A user of another site gets the Settings card only when this site lists
the user's home site under **sso_allow_tiqr_trusts**.  
Object types: site, unit, user

**sso_allow_tiqr_mgmt (bool, default: false)**  
Whether a user may manage their own tiqr phones on the Settings page of
the SSO portal: listing, enrolling, enabling and disabling, deleting,
making one the default token. It only works on top of
**sso_allow_tiqr**, which still has to allow tiqr.  
It is off by default, because which credentials a user may add or remove
on their own is something an install should hand out deliberately.
Signing in with a phone is not affected.  
Making one the default token also needs the current default token to be
one the portal manages, see **sso_allow_totp_mgmt**.  
Object types: site, unit, user

**sso_allow_tiqr_trusts (list)**  
Comma-separated list of sites this site trusts with tiqr phones of users
of other sites. It has to be set on **both** sites. Each of them makes a
decision of its own, and each can only read its own list, because the
parameter is not synced to other sites.

-   On the site whose SSO portal the user stands in front of, it lists
    the home sites of the users. This protects the portal site's backend
    and access groups from users of other sites. An enrolled phone is
    written into this site's backend and added to this site's SSO access
    group, roles and groups. So it gives a user of another site a new
    way in here. Without an entry the Settings card is not offered:
    listing, enrolling, enabling and disabling phones.

-   On the user's home site, it lists the portal sites. This protects
    the secrets of the home site's users from other sites. A phone
    delivers its tiqr secret to the site whose QR code it scanned, and
    that site passes it on to the home site. So whoever controls that
    site can capture the secret and sign in as the user. The home site
    only accepts such a request from a site in its list. It tells the
    requesting site by the certificate of its node, not by anything the
    request says.

Neither side can make the other's decision. The home site protects the
secrets of its users, the portal site protects its backend and access
groups from users of other sites. A site not in the list gets nothing.
There is no fallback to the local **sso_allow_tiqr**. Users of this site
need no entry.  
Without the trust the Settings card is not offered at all, so a phone
cannot be deleted there either. Signing in with a phone is not affected:
the phone answers a login with a one-time response, and its secret stays
on the phone.  
FIDO2 security keys need no such list, because a key never hands out its
secret.  
Object types: site

**sso_allow_fido2 (bool, default: true)**  
Whether FIDO2 security keys may be used in the SSO portal at all. That
covers signing in with one, and managing them on the Settings page,
registering another included. Managing them also needs
**sso_allow_fido2_mgmt**.  
Set it to false to refuse FIDO2 logins completely and to hide the card.
It takes **sso_allow_fido2_deploy** with it.  
It resolves fail-open: only an explicit false blocks. FIDO2 login is
older than this parameter and must not stop working because nobody set
it.  
Object types: site, unit, user

**sso_allow_fido2_mgmt (bool, default: false)**  
Whether a user may manage their own security keys on the Settings page
of the SSO portal: listing, registering, enabling and disabling,
deleting, making one the default token. It only works on top of
**sso_allow_fido2**, which still has to allow FIDO2.  
It is off by default, because which credentials a user may add or remove
on their own is something an install should hand out deliberately.
Signing in with a key is not affected.  
Making one the default token also needs the current default token to be
one the portal manages, see **sso_allow_totp_mgmt**.  
Object types: site, unit, user

**sso_max_fido2_token (int)**  

**sso_max_passkey_token (int)**  

**sso_max_tiqr_token (int)**  

**sso_max_totp_token (int)**  
How many security keys, passkeys, tiqr phones or authenticator apps one
user may hold in the Settings card of an SSO portal, between 1 and 128.
Unset means no limit.  
Counted are the tokens the card lists: the ones added at this portal,
and the default token when it is of that type. Once the limit is reached
the card shows no form to add another one, and adding one is refused.
That is checked on the user's home site, when the add starts and again
when it completes.  
Tokens an administrator creates, a deploy of the default token and
signing in are not affected.  
Object types: site, unit, user

**sso_show_fido2_button (bool, default: true)**  

**sso_show_tiqr_button (bool, default: true)**  
Whether the login mask offers the **Security Key** and **Sign in with
tiqr** buttons. It only says what the page shows. Whether the method may
be used is **sso_allow_fido2** and **sso_allow_tiqr**.  
It is a site parameter, because the mask is drawn before anybody has
typed a name. A per-user lookup would mean answering questions about who
exists.  
It resolves fail-open: only an explicit false hides a button.  
The button is the only way into that flow from the login mask, so hiding
it does take the method away in practice.  
The re-authentication page does not use this parameter. There the user
is known, and the page draws the one control their token can answer: a
password field, the security key button or the tiqr button.  
Object types: site

**sso_show_recover_link (bool, default: false)**  
Whether the login page shows the **Can't sign in?** link. It is off by
default.  
It works next to **allow_sso_account_recovery**, which is read per user.
This one hides the way in for the whole site, so a site that offers no
recovery at all does not show the flow. With it off, **/recover**
redirects back to **/login**.  
Object types: site

**tiqr_ocra_suite (str, default: OCRA-1:HOTP-SHA1-6:QH10-S)**  
OCRA suite (RFC 6287) offered to the app when a phone is enrolled.  
The suite a token uses is stored on the token itself, because the apps
bake it into the account at enrollment. So a change only applies to
phones enrolled from then on, and it never invalidates an existing
one.  
The default is what the tiqr apps have always used. Its bare **-S** is a
tiqr deviation from the RFC and means a 64 byte session field.  
Object types: site, unit, user

**tiqr_challenge_expiry (int, default: 180)**  
Seconds a tiqr login challenge stays answerable. The session key in the
QR code carries its own creation time, so this bounds the window without
any state on the server.  
There is no counter for wrong answers. Counting them would mean writing
state every node can see, from a route nobody has to authenticate to. So
what bounds guessing of the six digit response is this window together
with **sso_rate_limit_tiqr**. At the defaults that is 90 tries per
challenge, each one worth one in a million.  
Object types: site, unit, user

**tiqr_enrollment_expiry (int, default: 300)**  
Seconds an enrollment grant stays valid. That is how long the user has
to scan the enrollment QR code and finish in the app.  
Object types: site, unit, user

**tiqr_service_display_name (str)**  
Name the tiqr app shows for this service in its account list. Unset
means the realm name is used.  
The app files the account under an identifier made from this name, and
that identifier becomes the host part of the authentication URL. So only
characters that may appear there are accepted: letters, digits and
**-.\_\~!$&'()\*+,;=**. Setting a name with any other character is
refused, and the message names the characters.  
A space is a good example of why. Enrollment would still work, because
the app gets that part as JSON. But the login URL would be unparsable
and the app would refuse every QR code from then on.  
The identifier is written in lower case, because the app parses the URL
as one. The display name keeps the case it was given.  
Object types: site

**tiqr_auth_scheme (str, default: tiqrauth)**  
URL scheme of the authentication link handed to the phone. It has to
match the app the users have, and the stock tiqr apps register this one.
Change it only when you ship your own build of the app.  
Object types: site

**tiqr_enroll_scheme (str, default: tiqrenroll)**  
URL scheme of the enrollment link handed to the phone, alongside
**tiqr_auth_scheme**.  
Object types: site

**sso_rate_limit_login (str, default: 100/minute)**  
Rate limit per IP address on the **/login** POST route of the SSO
portal. It is a coarse guard against a flood from one source, and it is
generous on purpose, so that a NAT pool does not trip it under normal
load.  
The value is a Flask-Limiter expression, e.g. **100/minute** or
**1000/hour**. Several limits can be chained with a semicolon, e.g.
**3/minute; 1000/hour**.  
Object types: site

**sso_rate_limit_login_user (str, default: 10/minute)**  
Rate limit per user name on the **/login** POST route of the SSO portal.
This one is about guessing one account, whatever address the tries come
from. It works next to the **auto_disable** policy of authd.  
The key is the submitted user name, so users behind one NAT address do
not share a bucket.  
Object types: site

**sso_rate_limit_settings (str, default: 60/minute)**  
Rate limit on the **/settings/\*** routes of the SSO portal and on the
routes that change a credential: registering a token, changing a
password or a PIN, and so on. The user has signed in on all of them.  
The key is the name of the signed in user, so many tabs or a runaway
poll loop of one user cannot use up a shared bucket.  
Object types: site

**sso_rate_limit_recover (str, default: 20/minute)**  
Rate limit on the recovery routes of the SSO portal (**/recover**,
**/recover/complete/\***), which nobody has to authenticate to. It
bounds mail flooding and guessing of recovery links. A real recovery is
a handful of requests.  
The key is the submitted user name, so users behind one NAT address do
not share a bucket.  
Object types: site

**sso_rate_limit_tiqr (str, default: 30/minute)**  
Rate limit per IP address on the routes the tiqr apps call:
**/tiqr/metadata**, **/tiqr/enroll** and **/tiqr/auth**. Nobody has to
authenticate to them.  
The auth route takes the six digit response of a phone, and there is no
counter for wrong answers, so this limit and **tiqr_challenge_expiry**
are what bound guessing. Lower one of them if the default margin is not
the one you want.  
Object types: site

**auth_jwt_valid (time, default: 1m)**  
How long a JWT for a cross-site authentication stays valid.  
A user authenticates against one site and then uses another site of the
same realm. The site that did the authentication issues a short lived
JWT, and the other site verifies the authentication with it.  
Keep the value short, so that a leaked JWT can only be replayed for a
short time. The value takes time units, e.g. **60s** or **2m**, see
**CONFIG PARAMETERS** above.  
Object types: site

**sso_jwt_valid (time, default: 1D)**  
Validity of the JWT that the SSO portal (**httpd**) uses to authenticate
against **ssod** for a signed in user, for example to register or delete
a device token.  
The JWT is also the lifetime of the user's browser session in the
portal. When it expires, the user is signed out.  
Choose a value a little shorter than the session timeout of the SSO
access group, so that the JWT decides when the user is signed out and
not the access group session. The value takes time units, e.g. **12h**
or **1D**.  
Object types: site

**add_device_token_to_trash (bool, default: true)**  
Whether a device token the user deletes on the Settings page of the SSO
portal goes to the trash instead of being deleted at once. It can be
restored from there with **otpme-trash**(1). Set it to false to delete
such a token right away.  
The value is looked up on the user, then on the user's unit and the
units above it, then on the site. The first one found wins.  
Object types: site, unit, user

**add_fido2_token_to_trash (bool, default: true)**  
The same for a security key the user deletes on the Settings page.  
Restoring one puts the token back, not the credential on the key. The
key still holds the credential, so the restored token works again.  
There is one parameter per type, because what they hold differs. A
device token is a password somebody typed into a mail client, a security
key is a credential that exists only on that one device.  
Object types: site, unit, user

**add_passkey_to_trash (bool, default: true)**  
The same for passkeys, see **add_fido2_token_to_trash**.  
Object types: site, unit, user

**add_tiqr_token_to_trash (bool, default: true)**  
The same for a phone the user removes on the Settings page. Restoring
one puts the token back with its secret, so the phone that was enrolled
against it works again without being enrolled anew.  
Object types: site, unit, user

**add_totp_token_to_trash (bool, default: true)**  
The same for an authenticator app the user removes on the Settings page.
Restoring one puts the token back with its secret and its PIN, so the
app still produces valid codes for it.  
Object types: site, unit, user

**sso_allow_login_token_redeploy (bool, default: true)**  
Whether a user may deploy their login token again from the Settings page
of the SSO portal. That replaces it with a new token, of a type the
**sso_allow\_\*\_deploy** parameters allow.  
Turn it off where the administrator manages the login tokens of the
users. Otherwise a user could swap the token they were given for one of
their own choosing. The forced deploy of a token flagged for SSO deploy
is not affected.  
The value is looked up on the user, then on the user's unit and the
units above it, then on the site. The first one found wins.  
Object types: site, unit, user

**deploy_login_token_reauth (bool, default: true)**  
Whether deploying the default token again through the SSO portal needs a
fresh authentication. What that flow hands out replaces the token the
user signs in with, so without this an unlocked browser is enough to
take over the account.  
The user is sent to the re-auth page of the portal and lands back on the
deploy page. How long such an authentication stays fresh is
**sso_reauth_timeout**.  
The recovery deploy is not covered by this. It runs from the link in the
recovery mail and has no session to prove anything with, so the link
itself is the proof.  
Neither is the enrollment a token asks for itself, the one **otpme-token
enable_sso_deploy** sets — whatever this parameter says. There the token
the user signed in with is the only credential they have, and it is a
password token, so the re-auth would ask for the same password a second
time and say nothing. It stays for every other flow, where a token of
their own already exists: an OTP is good for one authentication, so
whoever phished one gets a session and is then asked for a second OTP
they do not have.  
The value is looked up on the user, then on the user's unit and the
units above it, then on the site. The first one found wins.  
Object types: site, unit, user

**deploy_fido2_token_reauth (bool, default: true)**  
The same before a security key is registered on the Settings page. Every
one of these enrolls a second way into the account, and the new
credential outlives the session it was created in.  
Object types: site, unit, user

**deploy_passkey_reauth (bool, default: true)**  
The same before a passkey is registered, see
**deploy_fido2_token_reauth**.  
Object types: site, unit, user

**deploy_tiqr_token_reauth (bool, default: true)**  
The same before a phone is enrolled, see
**deploy_fido2_token_reauth**.  
Object types: site, unit, user

**deploy_totp_token_reauth (bool, default: true)**  
The same before an authenticator app is added, see
**deploy_fido2_token_reauth**.  
Object types: site, unit, user

**deploy_device_token_reauth (bool, default: true)**  
The same before a device token is added, see
**deploy_fido2_token_reauth**.  
This is the one whose credential is a password on a screen, not a device
the user has to be holding. So it is also the one an install is most
likely to find in the way.  
Object types: site, unit, user

**sso_profile_edit_reauth (bool, default: true)**  
The same before an attribute or the photo is changed on the Profile
page, see **sso_allow_profile_edit**.  
That is no credential, but a mail address or a phone number can be where
a password reset or a second factor is sent to.  
Object types: site, unit, user

**sso_reauth_timeout (int, default: 120)**  
How long an authentication on the SSO portal stays fresh, in seconds.
The value takes time units, e.g. **2m**, and the lowest value is 60.  
It applies to every gate that asks for one: changing the recovery mail,
the **deploy\_\*\_reauth** flows and **sso_profile_edit_reauth**. It is
short on purpose. It is a window the user is working in, not a second
session.  
The Settings page asks for a new authentication once less than 30
seconds of the window are left. That applies to every add form —
security key, passkey, phone, authenticator app and device token — and
to the Profile editor. The user still has to type a name and touch a key
after the form opens, and a window that runs out in between would cost
them a second trip.  
The value is looked up on the user, then on the user's unit and the
units above it, then on the site. The first one found wins.  
Object types: site, unit, user

**reverse_proxy_ips (list)**  
Comma separated list of IP addresses of trusted reverse proxies. When a
request originates from one of these IPs, the **X-Forwarded-For** and
**X-Forwarded-Host** headers are used to find the real client address
and the requested host.  
A request from any other address ignores these headers, so a client
cannot fake where it comes from by setting them itself.  
Object types: site

**site_admin_blacklist (list)**  
Comma separated list of object OIDs (for example
**user\|myrealm/mysite/myuser**) that members of the **SITE_ADMIN** role
must not reach through that role alone.  
Being in the role normally gives access to every object of the site,
without any ACL check. For a listed object that shortcut is dropped, and
the ACLs on the object decide, like they do for anyone else. So an ACL
set on the object still gives access. The list takes the blanket
permission away, it does not override an ACL somebody granted on
purpose.  
The list is set as OIDs but stored as UUIDs. So an entry survives a
rename of the object, and a new object that later takes over the name
does not inherit it. An OID of an object that does not exist is
refused.  
The parameter is read from the site that handles the request, and it
lives on the site object itself. The role shortcut never applies there,
so site admins cannot take entries out of their own blacklist. That is
the same protection **realm**, **site** and **node** objects have
anyway, without being listed.  
This applies to the object interfaces, i.e. management and API. LDAP
checks its ACLs on its own path and is not affected.  
Object types: site

## OIDC Provider

These parameters are set per OIDC client. A value on the site or the
unit is the default for the clients below it.  
An OIDC client is the application that sends the user to OTPme to sign
in. The OIDC specs call it the Relying Party, RP for short, and OTPme
the OpenID Provider, OP.  
How the OP itself is run — switching it on, rotating the signing keys,
the pairwise secret — is in **otpme-site**(1).

**oidc_default_scopes (list)**  
Comma separated list of the scopes a new OIDC client is given. It is
read when the client is added, so a change does not touch the clients
that are already there.  
A name has to be the name of an existing **scope** object, and setting
an unknown one is refused. A site starts with the scopes **openid**,
**profile**, **email**, **address**, **phone**, **offline_access** and
**groups**, of which the first three are in this list. What each of them
hands out, and how a scope is granted at all, is in
**otpme-scope**(1).  
Example:

**otpme-site config *berlin* oidc_default_scopes
openid,profile,email,groups**

When the client is added, **--scopes** replaces this list,
**--add-scopes** comes on top of it, and **--no-default-scopes** leaves
it out, see **otpme-client**(1).  
Object types: site, unit

**oidc_email_attribute (str, default: mail)**  
The LDIF attribute the OIDC *email* claim is taken from. The default is
**mail**, the attribute of inetOrgPerson.  
A site that keeps mail aliases in **mailLocalAddress**, the way postfix
virtual or qmail do, sets that one here.  
Object types: site, unit

**oidc_logout_scope (str, default: sso)**  
What the OIDC */end_session* route does.

**sso**  
signs the user out completely. It also ends every OIDC session below the
SSO session, and it sends a backchannel logout to each client that
registered one.

**rp**  
only ends the OIDC session of the client that called. The SSO session
and the other clients stay signed in.

**rp** is for a client that wants its own, shorter session, independent
of the SSO session.  
Valid values: **sso**, **rp**.  
Object types: site, unit, client

**oidc_pkce_required (bool, default: true)**  
Whether PKCE (RFC 7636) is required in the authorize flow. OAuth 2.1
requires it for every client, so it is on by default.  
Switch it off on a single client only, and only for an old one that
cannot produce a **code_verifier** and a **code_challenge**.  
Object types: site, unit, client

**oidc_allow_plain_pkce (bool, default: false)**  
Whether the old PKCE method **plain** is accepted in the authorize
flow.  
With **plain** the challenge is the verifier, so whoever sees the
authorization request has both and PKCE protects nothing. OAuth 2.1
§4.1.1 leaves it to clients that cannot do **S256**; OTPme refuses it
unless this says otherwise. The only reason to turn it on is an old
client that has **plain** built in and cannot be changed.  
The discovery document never offers **plain**, whatever this is set
to.  
Object types: site, unit, client

**oidc_id_token_hint_max_age (time, default: 3M, i.e. 90 days)**  
How old an **id_token_hint** may be that */end_session* accepts.  
The **exp** of the token is not enforced on purpose. A user who signs
out an hour after the access token expired is a normal case. But without
any bound a years old ID Token from a backup could still drive a
logout.  
Lower the value where you need more assurance. It takes time units, e.g.
**7D**, **12h** or **2W**.  
Object types: site, unit, client

**oidc_access_token_ttl (time, default: 1h)**  
How long an OIDC access token is valid, and with it the ID Token issued
next to it. The default of one hour is what OAuth 2.1 suggests for
bearer tokens.  
Set it lower on a client that guards something valuable, e.g. **5m**,
and higher on an internal tool, e.g. **8h**. A refresh token is not
bound by this value but by the SSO session above it.  
It takes time units, e.g. **5m**, **1h** or **8h**.  
Object types: site, unit, client

**oidc_retired_max_age (time, default: 2h)**  
How long a signing key stays published after **otpme-site
renew_oidc_key** has retired it. For that long an application can still
check what the old key signed. After that the key is left out of */jwks*
and of the discovery document, and the next renewal removes it.  
Do not set it lower than the longest **oidc_access_token_ttl** in use.
An ID Token lives that long, and an application checks it with the keys
it is given.  
It takes time units, e.g. **2h** or **1D**.  
Object types: site

**oidc_acr_scheme (str, default: numeric)**  
Which Authentication Context Class Reference (*acr*) an ID Token
carries.

**numeric**  
writes a number, which is what most clients understand: **0** when no
factor is known, **1** with any factor, and **2** when the login was
hardware backed or used more than one factor. The numbers follow OIDC
Core §2 and ISO/IEC 29115.

**none**  
writes no *acr* claim at all.

The *amr* claim (RFC 8176), which says how the user signed in, is
written whenever the token is known, whatever this is set to.  
Valid values: **numeric**, **none**.  
Object types: site, unit, client

**oidc_id_token_user_claims (bool, default: false)**  
Whether the user claims of the granted scopes are put into the ID Token
as well. Those are **profile** with name, picture and so on, plus
**email**, **phone**, **address** and **groups**.  
It is off by default. In the authorization code flow OIDC Core §5.4
hands them out at */userinfo* only, and an ID Token is often passed on
as proof that the user signed in.  
Turn it on for a client that never calls */userinfo* and reads the ID
Token alone. The **user_oidc** app of Nextcloud works that way and gets
no name, mail address or photo without it.  
The claims of the ID Token itself — **sub**, **auth_time**, **amr**,
**acr** — are never replaced.  
Object types: site, unit, client

**oidc_avatar_dimensions (str, default: 300x300)**  
The size, as *width***x***height* in pixels, in which a client gets the
user's photo that the **picture** claim points to.  
The URL of that claim carries the client:

*/oidc/avatar/\<client_uuid\>/\<user_uuid\>.jpg*

The photo is resized when it is fetched, the same way as for
**user_photo_dimensions**.  
The default is the square Nextcloud wants. Set it to the value of
**user_photo_dimensions** for a client that should get the photo as it
is stored.  
The URL is not authenticated: whoever puts another client into it gets
the same photo in that client's size.  
Object types: site, unit, client

**oidc_require_consent (bool, default: false)**  
Whether OTPme asks the user at */authorize* whether the client may have
the data.  
It is off by default. Inside a company the administrator has already
decided per scope who may grant what, so one more click costs the user
time and decides nothing.  
Turn it on for a client that is open to the public or serves several
tenants, where the user should agree themselves.  
An agreement is remembered per user and client, the first time it is
given. A request that asks for more scopes than the remembered one asks
again. The OIDC request parameter **prompt=consent** always shows the
screen again, whatever was remembered.  
Object types: site, unit, client

## Share Notifications

**send_share_notifications (bool, default: false)**  
Whether the site tells the hosts that are online about a change of the
share permissions, so that they can act on it at once, e.g. mount or
unmount a share when it is enabled or disabled.  
The value is looked up in two steps. First on the token that makes the
change, and only there, without walking its parents. That lets a user
switch off the notifications their own changes cause. If the token has
no value, the object that is changed decides: the share or the user,
then its unit and the units above it, then the site.  
The options **--share-notify** and **--no-share-notify** of
**otpme-share**, **otpme-group**, **otpme-role**, **otpme-token** and
**otpme-user**(1) decide it for one command.  
Object types: site, unit, share, user, token

## Daemon Tuning

A daemon reads these when it starts. So a change takes effect once that
daemon was restarted:

> **otpme-controld restart \[*daemon*\]**

Without a daemon name every daemon is restarted.

**authd_workers (int, default: 16)**  
Number of preforked **authd** worker processes. They stay for as long as
the daemon runs, and that is what keeps their caches warm. So set this
for a normal day, not for the peak; the peak is what
**authd_max_workers** is for.  
Every listening socket gets its own pool, so a node that listens on a
unix socket and on TCP runs two of them.  
The value is looked up on the node, then on its unit and the units above
it, then on the site. The first one found wins.  
Object types: site, unit, node

**authd_max_workers (int, default: 64)**  
How far an **authd** worker pool may grow while every one of its workers
is busy.  
A worker is busy for as long as its connection lasts, and a login lasts
until the user has typed their password or OTP. So a whole department
arriving in the morning needs more workers than the rest of the day
does.  
Workers above **authd_workers** are forked when the pool runs full, and
they are stopped again once it has not been full for a minute. So the
extra memory is only spent during the rush, and the resident workers
keep seeing enough requests to hold their caches.  
A connection that arrives while the pool is at its maximum is not
refused. It waits in the listen backlog (**socket_backlog**) until a
worker is free. That the maximum was reached is logged, at most once a
minute:

All 64 workers busy and pool at its maximum. New connections wait in the
listen backlog

Set this to the same value as **authd_workers** to keep the pool at a
fixed size.  
Object types: site, unit, node

**authd_worker_threads (int, default: 0)**  
How many connections one **authd** worker serves at the same time, each
in a thread. **0**, the default, keeps a worker on the one connection it
accepted.  
A worker only uses threads once the pool sits at **authd_max_workers**
and every worker in it is busy. Up to that point another worker is the
better answer, because two connections in one worker share one GIL. At
that point the choice is no longer a slower login but no login: the
connection waits in the backlog with nobody to pick it up. What makes it
work is that a login spends most of its time waiting for the user to
type or to touch their token, and a thread waiting for input holds no
GIL.  
What it buys is room. How many connections may sit in a login at once
goes from **authd_max_workers** to that times this value. The room is
cheap: one more waiting connection costs a thread stack instead of a
process with caches of its own, so this can be set much higher than the
number of workers ever could.  
It is no defence against somebody who occupies connections on purpose.
They pay one place per connection either way, so a higher ceiling only
raises what it costs them. What keeps a connection from being held is
**authd_idle_timeout**.  
With a value above 0 every connection of that worker is served in a
thread, not only the ones after the first. It has to be that way: only a
worker inside its accept loop can hand a connection to a thread, and a
worker that served the first one itself would be out of that loop before
the pool is even known to be full.  
Object types: site, unit, node

**authd_idle_timeout (int, default: 120)**  
Seconds an **authd** connection may sit there without asking anything
before it is closed. A worker serves one connection at a time, so a
client that connects and then says nothing holds one for good --
**authd_workers** of those and nobody authenticates anywhere in the
realm any more. Only the wait for the next request is counted, never the
work on one, so a token that takes its time (a push token waiting for
the user to confirm) is not affected. Set to **0** to turn it off.  
A login does wait here: after the server has asked for a password or
OTP, the next request arrives only once the user has typed it, so this
cannot be shorter than a person at a prompt needs. The default matches
the **sshd**(8) **LoginGraceTime** of 120 seconds, and **login**(1)
gives 60 seconds (**LOGIN_TIMEOUT** in **login.defs**(5)), so nothing
coming through PAM holds a connection longer than that anyway.  
Treat this as a reaper for silent and dead connections, not as a defence
against a deliberate attacker: whatever a real login is allowed here is
available to anyone who sends one request and then stops talking.  
Object types: site, unit, node

**socket_backlog (int, default: 1024)**  
Length of the accept queue the kernel keeps for the listening sockets of
the OTPme daemons. A connection the kernel has finished on its own waits
in there until a worker calls accept().  
This is what carries a login storm while every worker is busy. A client
whose connection waits in the queue notices nothing but the delay. One
that does not fit in is refused: on a unix socket that is an
**ECONNREFUSED** right away, on TCP the SYN is dropped and the client
tries again a few seconds later.  
The kernel caps the value at **/proc/sys/net/core/somaxconn**, so raise
that as well if you set a higher one.  
On a host this matters for **backupd** and for the unix socket of
**hostd**. The **httpd** of an SSO host runs gunicorn, which brings its
own backlog, and **confd** listens on nothing at all.  
The value is looked up on the node or host, then on its unit and the
units above it, then on the site. The first one found wins, and without
a value anywhere the built-in 1024 is used.  
Object types: site, unit, node, host

**ldapd_processes (int, default: 4)**  
Number of worker processes **ldapd** answers LDAP requests with. One
process cannot use more than one core, so raise this on a node where
ldapd runs out of CPU. The workers share the listen port with
SO_REUSEPORT.  
Every worker keeps its own LDIF caches. So more workers cost memory, and
each single one sees fewer requests to keep its caches warm with — see
also **ldap_shared_cache**.  
The value is looked up on the node, then on its unit and the units above
it, then on the site. The first one found wins.  
Object types: site, unit, node

**ldap_cache (bool, default: true)**  
Whether the **ldapd** worker processes cache anything at all: the
entries they built, the searches they answered, and the objects those
came from.  
With it off every search builds its entries from the backend again. That
costs time on a search that is repeated, because encoding a result entry
is more work than everything else a cached search does put together.  
What it buys is that nothing of a search outlives it. A worker that
answered one large search otherwise keeps those entries for as long as
they stay valid, so its memory follows the largest search it has seen,
once per worker. Turn it off where that matters more than the time a
search takes, or to find out whether a wrong answer comes from a
cache.  
This is only about what a worker keeps for itself. What the workers hand
each other is a setting of its own and keeps working with this one off,
so turn off **ldap_shared_cache** as well to have a worker answer every
search from the backend.  
The value is looked up on the node, then on its unit and the units above
it, then on the site. The first one found wins.  
Object types: site, unit, node

**ldap_shared_cache (bool, default: true)**  
Whether the **ldapd** worker processes share what they looked up with
each other: search results and resolved search bases.  
With it off every worker has its own caches only. That is useful as a
comparison when you suspect the shared caches. It only means something
when **ldapd_processes** is greater than 1.  
It works next to **ldap_cache**. What the workers share with each other
is still shared when the per-worker caches are off.  
The value is looked up on the node, then on its unit and the units above
it, then on the site. The first one found wins.  
Object types: site, unit, node

**ldap_shared_cache_time (int, default: 3600)**  
Seconds a cached search result and a resolved search base stay valid in
the **ldapd** caches. It is also the expiry of the cache keys
themselves, so nothing has to be cleaned up after a worker that went
away.  
This is not what keeps the caches correct: a changed object drops its
entries at once. The value only says how long an entry nobody touched
sits around, so lowering it costs hits and buys no correctness. It
applies to the shared caches as well as to the per-worker ones.  
The value is looked up on the node, then on its unit and the units above
it, then on the site. The first one found wins.  
Object types: site, unit, node

**httpd_ssl_socket_uri (str, default: tcp://\[::\]:443)**  
The socket the **httpd** of the SSO portal listens on, as
**tcp://address:port**.  
The value is looked up on the host or node, then on its unit and the
units above it, then on the site. The first one found wins. So one SSO
host can bind another port, for example when a reverse proxy sits in
front of it.  
Object types: site, unit, node, host

**httpd_socket_uri (str, default: tcp://\[::\]:80)**  
The socket of the plain HTTP listener that serves the CA certificates of
the realm and the site (**realm_ca.pem**, **site_ca.pem**), as
**tcp://address:port**. A host that has no OTPme trust yet gets them
from there.  
The value is looked up like **httpd_ssl_socket_uri**. To switch the
listener off, set **httpd_workers** to 0.  
Object types: site, unit, node, host

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
Whether **otpme-tool who** may be run on a host that is not a node. The
request goes to **idled**, which answers who is logged in where.  
Off by default, so that only a node sees that list. Set it to true to
let every host of the site ask as well. To let single hosts ask, leave
it off and list them in **allow_who** instead. While this is on,
**allow_who** is not read.  
Whatever it is set to, a peer of another site or of another realm is
always refused.  
Object types: site

**allow_who (list, default: empty)**  
The hosts that may run **otpme-tool who** while **allow_who_from_hosts**
is off. What they see is every user logged in on the site, with login
token, client IP and session.

Nodes may ask whatever this is set to.

Give the host by name, several of them separated by commas, and **-a**
to add one to those already there:

    otpme-site config berlin allow_who berlin-host1
    otpme-site config -a berlin allow_who berlin-host2

The hosts are kept by UUID and shown by name again, as with
**allow_user_messages**. Only an admin may change it.

Whatever it is set to, a peer of another site or of another realm is
always refused.

Object types: site

**allow_user_messages (list, default: empty)**  
The hosts that may send messages to the users of this site. See
**message** in **otpme-tool**(1).

Nodes may send messages whatever this is set to. A host may not, until
it is listed here. Add a host where something on it has to reach the
people who use it.

Give the host by name, several of them separated by commas, and **-a**
to add one to those already there:

    otpme-site config berlin allow_user_messages berlin-host1
    otpme-site config -a berlin allow_user_messages berlin-host2

The hosts are kept by UUID and shown by name again. A name belongs to a
host only for as long as it has it, so a host that is removed takes its
permission with it, and a new host of the same name does not inherit it.

A message is shown in a window on the desktop of the user, so a host
that may send one can put text in front of somebody. That is why it is
one host at a time and not a switch for all of them, and why only an
admin may change it.

Whatever it is set to, a peer of another site or of another realm is
always refused.

Object types: site

**preferred_master_node (str)**  
Name of the node that **clusterd** should make the master of this site,
as soon as that node is up and the cluster has quorum.  
If another node is master, clusterd hands the role over in an orderly
way. It waits until the cluster journal is worked off before it does. If
the preferred node is master already, nothing happens.  
The handover is done once after clusterd starts, not again while it
runs. A restart of the daemon makes it check again.  
Leave it unset to let the normal election pick any node that can take
the role.  
Object types: site

## Connection Limits

How many connections a daemon serves at the same time. Use them to keep
a busy node from running out of connections, or to hold a quiet site
back on purpose. The defaults fit a normal installation; raise one only
when the traffic asks for it.

A connection that arrives above the limit is closed at once. It does not
wait, which is the difference to **socket_backlog**, and the client sees
the connection go away. The daemon logs that it reached its limit, at
most every five seconds, and says afterwards how many messages it left
out.

Only the daemons below have such a parameter. **authd** has none: its
limit is 1024, built in, and its worker pool does not enforce it — what
bounds authd is **authd_max_workers** together with
**authd_worker_threads**. **httpd** runs gunicorn with its own settings,
and **hostd** and **confd** have no parameter either.

Each value is looked up on the node (or the host, where that is
allowed), then on its unit and the units above it, then on the site. The
first one found wins.

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
Maximum concurrent client connections accepted by **backupd**.  
It can also be set on a host, because a host can be the backup target
that takes the backups.  
Object types: site, unit, node, host

## Request Limits

**max_decompressed_size (size, default: 256M)**  
How large a single request may be *after* it was decompressed. It guards
against a small compressed message that blows up into something that
eats the memory of the daemon.  
A daemon reads the value when it starts, from its own node or host
object, and the decompress path enforces it.  
The value is looked up on the node or host, then on its unit and the
units above it, then on the site. The first one found wins, and without
a value anywhere the built-in 256M is used.  
It takes human sizes, e.g. **256M** or **1G**.  
Object types: site, unit, node, host

## Description and Info Length Limits

**max_description_len (int, default: 1024)**  
How long the description of an object may be, in characters. It is
checked when the description is changed, never when an object is loaded,
so a lower limit does not break what is already there.  
The value is looked up on the object, then on its unit and the units
above it, then on the site. The first one found wins, and without a
value anywhere the built-in default is used.  
Object types: site, unit

**max_info_len (int, default: 16384)**  
How long the info text of an object may be, in characters, per language.
It is checked when the text is changed, never when an object is
loaded.  
An info text is written per language (**otpme-role info --language**),
and a few paragraphs fit in one. Two things read it today:

-   The info of a role named by **device_token_roles** is shown in the
    Settings page of the SSO portal, so that the user reads what the
    role is for.

-   The info of the SSO access group of the site is the text of the
    recovery mail, one per language. Without one OTPme sends the text it
    ships with, in the language of the user.

The value is looked up on the object, then on its unit and the units
above it, then on the site. The first one found wins, and without a
value anywhere the built-in default is used.  
Object types: site, unit

## Name Length Limits

How long the name of an object may be, one parameter per object type.

It is checked when an object is added and when it is renamed, never when
one is loaded. So a lower limit leaves the objects that are already
there alone, and they keep working.

Lower them to keep LDAP DNs, file paths and the output of the commands
readable. Raise one only when you know that what reads those names can
take it.

Each value is looked up on the object, then on its unit and the units
above it, then on the site. The first one found wins, and without a
value anywhere the built-in default is used.

All of them are of type **int** and can be set on **site** and **unit**.

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

**max_vlan_name_len (int, default: 64)**  
Cap for VLAN names.

## Backup

**backup_enabled (bool)**  
Whether this object is backed up at all. Without it a backup of the
object is refused, so it is the switch an administrator turns on once
the other parameters are in place.  
Object types: site, unit, node, share

**backup_exclude_special (bool)**  
Whether special files are left out of the backup: block and character
devices, FIFOs and sockets. Only the file itself is meant, never the
data behind a device.  
Object types: site, unit, node, share

**backup_server (str)**  
The node or host that takes the backups of this object.  
It is set by name, and it is shown as the FQDN of that node or host. A
node or host that does not exist is refused.  
Object types: site, unit, node, share

**backup_time (str)**  
The time of day a backup may run, as *HH:MM***-***HH:MM*, e.g.
**02:00-03:00**. Both times are checked when the value is set.  
Object types: site, unit, node, share

**backup_interval (time)**  
How much time passes between two backups of this object. It takes time
units, e.g. **1h** or **1D**, and it is shown in those units.  
Object types: site, unit, node, share

**backup_retry_interval (time, default: 5m)**  
How long a backup waits before it tries again, when the repository is in
somebody else's hands. That happens when another backup, a restore or a
repack is running in it. Such a backup has not failed, so it does not
report one: the same attempt works once the other one is done. It takes
time units, e.g. **5m**, and it is shown in those units.  
Object types: site, unit, node, share

**backup_retry_count (int, default: 12)**  
How many more times a backup tries when it found the repository in use.
The tries end with the backup window in any case, so this only bounds a
window that stands open all day. With **0** a backup does not wait at
all, and a repository in use makes it fail.  
The time of the last backup stays as it is while a backup waits. No
backup ran, so **backup_interval** must not count the waiting as the
backup of this window. It is written when the backup runs, and when the
last try gives up.  
Object types: site, unit, node, share

**backup_key (str)**  
The AES key the backups of this object are encrypted with, as 64 hex
characters. OTPme makes one from 32 random bytes when the object is
created, so there is no need to set one by hand.  
It is stored encrypted with the key of the site. **show_config** shows
it in clear to whoever may read it, and **\<hidden\>** where the site
key is not available.  
Object types: site, unit, node, share

**backup_repo_password (str)**  
The password the backup server asks for.  
It is stored encrypted with the key of the site, like **backup_key**.  
Object types: site, unit, node, share

**backup_report_enabled (bool, default: false)**  
Whether a mail is sent about a backup run that finished, whether it
worked or failed. With it off none of the other **backup_report\_\***
parameters does anything.  
Where the mail is sent is the shared **smtp_relay\_\*** parameters
below.  
Object types: site, unit, node, share

**backup_report_mode (str, default: all)**  
Which backup runs are reported, and how.

**all**  
one mail per run

**success**  
only a run that worked

**error**  
only a run that failed

**summary**  
one mail for all backup runs of the host, instead of one per backup
object

The summary has one line per object: name, status, when it finished, how
long it took, how many files, and how much was backed up and stored — or
the error of a run that failed.  
It is an HTML mail with a table, failed runs in red, and it carries a
plain text version for mail programs that show no HTML. It is sent as
soon as the last running backup has finished. Objects with a different
**backup_report_mail_to** get a summary of their own.  
Object types: site, unit, node, share

**backup_report_mail_from (str)**  
The address the report mail comes from, in the envelope and in
**From:**.  
Object types: site, unit, node, share

**backup_report_mail_to (str)**  
The address the report mail goes to.  
Object types: site, unit, node, share

**smtp_relay_server (str, default: 127.0.0.1)**  
The SMTP relay OTPme hands its mails to. Every mail goes through it: the
backup reports, the recovery mail of the SSO portal, and whatever comes
later.  
Object types: site, unit, node, share

**smtp_relay_port (int, default: 25)**  
TCP port of the SMTP relay.  
Object types: site, unit, node, share

**smtp_relay_starttls (bool, default: false)**  
Whether OTPme sends **STARTTLS** before it hands the message over.  
Object types: site, unit, node, share

**smtp_relay_auth (bool, default: false)**  
Whether OTPme authenticates to the relay, with **smtp_relay_username**
and **smtp_relay_password**.  
Object types: site, unit, node, share

**smtp_relay_username (str)**  
Login name for SMTP authentication.  
Object types: site, unit, node, share

**smtp_relay_password (str)**  
The password for the SMTP authentication.  
It is stored encrypted with the key of the site, like **backup_key**.
**show_config** shows **\<hidden\>** where that key is not available.  
Object types: site, unit, node, share

**backup_mode (str)**  
How the backup data is stored.

**pack**  
in pack files, which needs less space

**tree**  
in pack files and, on top of that, in a directory tree that looks like
the files it came from

**tree** is what a restore share needs, because that share is mounted
over FUSE and reads the tree.  
There is no default for every object. Without this parameter a share is
backed up as **tree** and a node as **pack**. Setting it overrides
that.  
Object types: node, share

**backup_excludes (list)**  
Comma separated list of patterns that are left out of the backup.  
Object types: node, share

**backup_includes (list)**  
Comma separated list of patterns that are taken into the backup.  
Object types: node, share

**backup_script (str)**  
The OTPme script **backupd** runs around every backup, as a path
relative to the scripts unit.  
It is called with a **pre** hook before the backup and a **post** hook
after it. An exit code other than 0 stops the run.  
The default is the **backup_script.sh** that OTPme ships, in the default
scripts unit. Only an admin may set this parameter.  
Object types: site, unit, share, node

## HOTP Tokens

A value of this section is written to the token when the token is added,
except where it says otherwise. A later change of the parameter leaves
the tokens that exist alone.

**hotp_check_range (int, default: 32)**  
How many counter values ahead of the one it has stored OTPme tries when
a HOTP token signs in. A token whose counter ran away further than that
needs a resync.  
The value is written to the token as its counter check range. Change it
on a single token with **counter_check_range**, see
**otpme-token**(1).  
Object types: site, unit, user

**hotp_resync_check_range (int, default: 1024)**  
How far a resync of a HOTP token looks, around the counter the token has
stored. It looks in both directions, so the window is twice this
value.  
This one is read at every resync, not written to the token.  
Object types: site, unit, user

**hotp_default_pin_len (int, default: 4)**  
How many digits the PIN of a new HOTP token has. It is also the length
of a PIN that **gen_pin** makes later.  
Object types: site, unit, user

**hotp_secret_len (int, default: 10)**  
How many bytes the secret of a new HOTP token has.  
Object types: site, unit, user

## TOTP Tokens

**totp_default_pin_len (int, default: 4)**  
How many digits the PIN of a new TOTP token has. The SSO portal uses it
as well when it adds an authenticator app.  
Object types: site, unit, user

**totp_secret_len (int, default: 10)**  
How many bytes the secret of a new TOTP token has. It is written to the
token when the token is added.  
Object types: site, unit, user

## mOTP Tokens

The first three of these are written to the token when it is added, and
they are used by a **yubikey_hmac** token as well, although their names
say mOTP. A later change leaves the tokens that exist alone.

**motp_validity_time (int, default: 60)**  
How many seconds an OTP of such a token is good for.  
Object types: site, unit, user

**motp_timedrift_tolerance (int, default: 15)**  
How many seconds the clock of the token may be off.  
Object types: site, unit, user

**motp_len (int, default: 6)**  
How many characters an OTP of such a token has.  
Object types: site, unit, user

**motp_default_pin_len (int, default: 4)**  
How many digits the PIN of a new mOTP token has.  
Object types: site, unit, user

**motp_secret_len (int, default: 16)**  
How many bytes the secret of a new mOTP token has.  
Object types: site, unit, user

## Static Password Tokens

**default_static_pass_len (int, default: 10)**  
How many characters a generated password of a static password token has.
Which characters it may use comes from the password policy of the
user.  
Object types: site, unit, user

## Hardware Tokens

**check_fido2_attestation_cert (bool, default: false)**  
Whether the attestation certificate of a FIDO2 token is verified when
the token is deployed.  
Verified are two things: that the certificate is inside its validity
dates, and that its signature comes from the FIDO2 CA certificate of the
site that matches its issuer. Those CA certificates live on the site
object, see **otpme-site**(1).  
It is off by default, because a deployment fails when the site has no CA
certificate for the issuer of that key. Turn it on where you hand out
keys of a known make and have their CA certificate.  
Object types: site, unit, user, token

**check_u2f_attestation_cert (bool, default: false)**  
The same for a U2F token.  
Object types: site, unit, user, token

## OTP Push Tokens

**otp_push_default_pass_len (int, default: 6)**  
How many characters a password is that OTPme generates and pushes to the
user.  
Object types: site, unit, user

**default_otp_push_script (str)**  
The script that delivers the password to the user, e.g. by SMS or by
mail. It is set as a path relative to the scripts unit, and the default
is the **push_script.sh** that OTPme ships.  
Object types: site, unit

## YubiKey HMAC Tokens

**otpme_hmac_otp_len (int, default: 16)**  
How many characters an OTP of such a token has. It is written to the
token when the token is added.  
Object types: site, unit, user

**otpme_hmac_secret_len (int, default: 16)**  
How many bytes the secret of such a token has.  
These tokens also use **motp_validity_time** and
**motp_timedrift_tolerance**.  
Object types: site, unit, user

## Hash Parameters

These say how a password is hashed. Only the parameters of the hash that
**default_pw_hash_type** names are used; the others sit there without
doing anything.

A value is looked up on the token, then on the user, then on the user's
unit and the units above it, then on the site. The first one found wins,
and without a value anywhere the built-in default is used.

A password hash keeps the values it was made with, so a change only
applies to passwords set from then on.

Note the names: Argon2d spells it **iter** where Argon2i and Argon2id
spell it **iterations**.

## Hash Parameters (Argon2i)

**default_pw_hash_argon2i_iterations (int, default: 2)**  
How many passes Argon2i makes over its memory. More passes cost more
time.  
Object types: site, unit, user, token

**default_pw_hash_argon2i_min_mem (int, default: 65536)**  
The lower bound of the memory in KB, and
**default_pw_hash_argon2i_max_mem** the upper one.  
Both are only used where the caller asks for the memory to be chosen at
run time, and password hashing never does: it always uses 64 MiB. The
one place that asks is the key of the offline tokens, and that one takes
its values from the options of **pam_otpme**(8), not from here. So
changing these two changes nothing today.  
Object types: site, unit, user, token

**default_pw_hash_argon2i_max_mem (int, default: 262144)**  
See **default_pw_hash_argon2i_min_mem**.  
Object types: site, unit, user, token

**default_pw_hash_argon2i_threads (int, default: 1)**  
How many threads Argon2i works with.  
Object types: site, unit, user, token

**default_pw_hash_argon2i_key_len (int, default: 128)**  
How many bytes the hash has.  
Object types: site, unit, user, token

## Hash Parameters (Argon2d)

**default_pw_hash_argon2d_iter (int, default: 2)**  
How many passes Argon2d makes over its memory.  
Object types: site, unit, user, token

**default_pw_hash_argon2d_min_mem (int, default: 65536)**  
The lower bound of the memory in KB, see
**default_pw_hash_argon2i_min_mem**.  
Object types: site, unit, user, token

**default_pw_hash_argon2d_max_mem (int, default: 262144)**  
The upper bound of the memory in KB, see
**default_pw_hash_argon2i_min_mem**.  
Object types: site, unit, user, token

**default_pw_hash_argon2d_threads (int, default: 1)**  
How many threads Argon2d works with.  
Object types: site, unit, user, token

**default_pw_hash_argon2d_key_len (int, default: 128)**  
How many bytes the hash has.  
Object types: site, unit, user, token

## Hash Parameters (Argon2id)

**default_pw_hash_argon2id_iterations (int, default: 2)**  
How many passes Argon2id makes over its memory.  
Object types: site, unit, user, token

**default_pw_hash_argon2id_min_mem (int, default: 65536)**  
The lower bound of the memory in KB, see
**default_pw_hash_argon2i_min_mem**.  
Object types: site, unit, user, token

**default_pw_hash_argon2id_max_mem (int, default: 262144)**  
The upper bound of the memory in KB, see
**default_pw_hash_argon2i_min_mem**.  
Object types: site, unit, user, token

**default_pw_hash_argon2id_threads (int, default: 1)**  
How many threads Argon2id works with.  
Object types: site, unit, user, token

**default_pw_hash_argon2id_key_len (int, default: 128)**  
How many bytes the hash has.  
Object types: site, unit, user, token

## Hash Parameters (PBKDF2)

**default_pw_hash_pbkdf2_iter (int, default: 100000)**  
How many rounds PBKDF2 makes. More rounds cost more time.  
Object types: site, unit, user, token

**default_pw_hash_pbkdf2_algo (str, default: SHA256)**  
The hash PBKDF2 works with.  
Object types: site, unit, user, token

**default_pw_hash_pbkdf2_key_len (int, default: 128)**  
How many bytes the hash has.  
Object types: site, unit, user, token

## Hash Parameters (HKDF)

**default_pw_hash_hkdf_algo (str, default: SHA256)**  
The hash HKDF works with.  
Object types: site, unit, user, token

**default_pw_hash_hkdf_key_len (int, default: 32)**  
How many bytes the key has.  
Object types: site, unit, user, token

# FILES

*/etc/otpme/otpme.conf*  
The configuration of this host or node: which realm and site it belongs
to, where its data lies, and how it talks to its backends. The other
files below */etc/otpme/* are in **otpme.conf**(5).

*/var/lib/otpme/*  
The data of this host: the objects, the indexes and the caches.

*/var/log/otpme/*  
The log files, one per daemon.

*\~/.otpme/otpme.conf*  
The settings of one user, e.g. which agent to talk to.

# SEE ALSO

**otpme**(1), **otpme-acls**(7), **otpme.conf**(5), **pam_otpme**(8),
**otpme-accessgroup**(1), **otpme-backup**(1), **otpme-ca**(1),
**otpme-client**(1), **otpme-cluster**(1), **otpme-deploy**(1),
**otpme-device**(1), **otpme-dictionary**(1), **otpme-group**(1),
**otpme-host**(1), **otpme-inventory**(1), **otpme-mount**(1),
**otpme-node**(1), **otpme-policy**(1), **otpme-pool**(1),
**otpme-realm**(1), **otpme-resolver**(1), **otpme-role**(1),
**otpme-scope**(1), **otpme-script**(1), **otpme-share**(1),
**otpme-site**(1), **otpme-token**(1), **otpme-tool**(1),
**otpme-trash**(1), **otpme-unit**(1), **otpme-user**(1),
**otpme-vlan**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2026 the2nd. License: GPLv3
