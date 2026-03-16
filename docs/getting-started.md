# Getting Started with OTPme

This guide walks through the initial setup of an OTPme realm and explains
common day-to-day administration tasks using a practical example.

## Prerequisites

### Testing without hosts and clients

If you just want to try out OTPme on a single node without setting up hosts or
RADIUS clients, you can initialize the realm with `localhost 127.0.0.1` as the
node FQDN and address. You can always migrate to a fully functional setup later.

### DNS records for a production setup

When using OTPme with real hosts and clients, the following DNS records are
required. The example uses the realm `otpme.org`, site `muenchen` and a
floating cluster IP `192.168.1.100`:

```
$ORIGIN _tcp.muenchen.otpme.org.
_otpme-join    SRV 10 1 2024 login.muenchen.otpme.org.
_otpme-login   SRV 10 1 2020 login.muenchen.otpme.org.
_otpme-realm   TXT "otpme.org"
_otpme-site    TXT "muenchen"

$ORIGIN muenchen.otpme.org.
login          A   192.168.1.100
node1          A   192.168.1.1
node2          A   192.168.1.2
```

`node1`, `node2` etc. must match the hostnames and IPs of your actual nodes.

### Load balancing

For load-balanced authentication and login requests across multiple nodes, set
an auth FQDN for the site and add a round-robin DNS record for it:

```bash
otpme-site auth_fqdn muenchen auth.muenchen.otpme.org
```

```
$ORIGIN muenchen.otpme.org.
auth    A   192.168.1.1
        A   192.168.1.2
```

If you only have one site you can use the realm domain directly for all records
(e.g. `auth.otpme.org` instead of `auth.muenchen.otpme.org`).

## 1. Initialize a Realm

The first step is to initialize a realm. This creates the root CA, the master
site, and the first node. The positional arguments are the realm name, the site
name, the FQDN of the node and (optionally) its IP address.

```bash
otpme-realm init \
    --country DE \
    --state Bayern \
    --locality Muenchen \
    --organization "OTPme" \
    --ou IT \
    --email admin@otpme.org \
    --ca-valid 3650 \
    --ca-key-len 4096 \
    --site-valid 3650 \
    --site-key-len 4096 \
    --node-valid 3650 \
    --node-key-len 4096 \
    --dicts english,en-top10000,common-passwords,us-female,us-male,us-surnames,abbreviations-it \
    --id-ranges "uidNumber:s:70000-80000,gidNumber:s:70000-80000" \
    otpme.org muenchen login.otpme.org 192.168.1.100
```

| Option | Description |
|--------|-------------|
| `--country` / `--state` / `--locality` | Location fields for CA certificates |
| `--organization` / `--ou` / `--email` | Organisation fields for CA certificates |
| `--ca-valid` | CA certificate validity in days (3650 = 10 years) |
| `--ca-key-len` | CA key length in bits |
| `--site-valid` / `--site-key-len` | Validity and key length for the site certificate |
| `--node-valid` / `--node-key-len` | Validity and key length for the node certificate |
| `--dicts` | Word dictionaries loaded into the password strength checker |
| `--id-ranges` | UID/GID ranges assigned to this realm |

## 2. Start the Daemons

```bash
otpme-controld start
```

## 3. Allow Local Management Without OTPme Login

To allow management commands when logged in to the node directly (without
authenticating to OTPme), set the following option in the configuration file:

`/etc/otpme/otpme.conf`
```
USE_MGMTD_SOCKET="True"
```

## 4. Configure WLAN Access

A common use case is authenticating WLAN clients via RADIUS. Create an access
group and a RADIUS client (the access point). When a client is added, OTPme
displays the RADIUS shared secret for that client.

```bash
otpme-accessgroup add wlan
otpme-accessgroup description wlan "WLAN Access"
otpme-accessgroup show

# Adding a client shows the RADIUS secret.
otpme-client add ap01 192.168.1.10
otpme-client access_group ap01 wlan
```

## 5. Add a User

```bash
otpme-user add alice
```

When a user is created, OTPme generates a default login token and displays its
QR code and PIN. This token is used for realm logins and group/role membership
(see later sections). You can display the user's full configuration at any time:

```bash
otpme-user show alice
```

## 6. Add a WLAN Token

Additional tokens can be created for specific services. The following creates a
password token with MS-CHAPv2 support (required by most RADIUS/WLAN setups):

```bash
otpme-token --type password add --enable-mschap alice/notebook-wlan
# Set a custom password if you don't want the generated one.
otpme-token --type password password alice/notebook-wlan
```

## 7. Grant WLAN Access Directly via Token

The simplest way to grant access is to add the token directly to the access
group:

```bash
otpme-accessgroup add_token wlan alice/notebook-wlan
otpme-accessgroup list_tokens wlan

# Verify authentication.
otpme-auth verify --socket alice <password> ap01
```

## 8. Grant WLAN Access via Role (Recommended)

Directly assigning tokens to access groups does not scale well. Using roles
makes it easy to grant or revoke access for groups of users at once. Remove the
direct token assignment and use a role instead:

```bash
# Remove direct token assignment.
otpme-accessgroup remove_token wlan alice/notebook-wlan
# Confirm that access is gone.
otpme-auth verify --socket alice <password> ap01

# Create a role and assign it to the access group.
otpme-role add wlan-user
otpme-accessgroup add_role wlan wlan-user

# Add the token to the role.
otpme-role add_token wlan-user alice/notebook-wlan

# Confirm that access is working again.
otpme-auth verify --socket alice <password> ap01
```

## 9. Restrict Login Times with Policies

Policies can restrict when logins are allowed. The built-in `workhours_login`
policy (and the `weekend_login` policy) are good examples. Policies can be
applied to access groups or directly to users:

```bash
# Restrict logins via the access group.
otpme-accessgroup add_policy wlan workhours_login
otpme-auth verify --socket alice <password> ap01
otpme-accessgroup remove_policy wlan workhours_login

# Restrict logins via the user.
otpme-user add_policy alice workhours_login
otpme-auth verify --socket alice <password> ap01
otpme-user remove_policy alice workhours_login
```

## 10. Disable and Enable Users and Tokens

Disabling a user prevents all logins for that user. Individual tokens can also
be disabled independently:

```bash
# Disable/enable a user.
otpme-user -f disable alice
otpme-auth verify --socket alice <password> ap01
otpme-user -f enable alice

# Disable/enable a single token.
otpme-token -f disable alice/notebook-wlan
otpme-auth verify --socket alice <password> ap01
otpme-token -f enable alice/notebook-wlan
```

## 11. Login Failure Limits

You can configure a maximum number of failed login attempts per access group.
After the limit is reached the user is blocked for that access group:

```bash
otpme-accessgroup max_fail wlan 3

# Three failed attempts will block the user.
otpme-auth verify --socket alice $RANDOM ap01
otpme-auth verify --socket alice $RANDOM ap01
otpme-auth verify --socket alice $RANDOM ap01
otpme-user show alice

# Unblock the user manually.
otpme-user unblock alice wlan

# Or configure an automatic unblock after a timeout.
otpme-accessgroup max_fail_reset wlan 1m
```

## 12. Auto Disable

Users and tokens can be configured to disable themselves automatically after a
given time. This is useful for temporary accounts or time-limited access:

```bash
# Disable alice automatically after 1 minute (for testing).
otpme-user auto_disable alice +1m
# Wait a minute, then check.
otpme-user show alice

# Remove the auto disable.
otpme-user auto_disable alice 0
otpme-user -f enable alice
```

Time suffixes: `m` = minutes, `h` = hours, `D` = days, `W` = weeks.

## 13. Groups

Groups map to POSIX groups on the node. The default group of a user becomes
their primary group. It takes a moment for `otpme-hostd` to sync changes to
system users; you can trigger a manual sync with `otpme-tool sync`:

```bash
# Create a management group and make it alice's default group.
otpme-group add management
otpme-user group alice management
otpme-user show alice

otpme-tool sync
id alice

# Add a staff group and add alice's login token to it.
otpme-group add staff
otpme-group add_token staff alice/login
otpme-tool sync
id alice

# Inspect the group.
otpme-group show staff$
otpme-group list_tokens staff
otpme-group list_users staff
```

## 14. Role-Based Group Membership (Recommended)

Managing group membership via tokens directly does not scale well. Using roles
allows you to control group membership for many users at once:

```bash
# Remove the direct token assignment.
otpme-group remove_token staff alice/login
otpme-tool sync
id alice

# Create a role and assign it to the group.
otpme-role add management-user
otpme-group add_role staff management-user

# Add alice's login token to the role.
otpme-role add_token management-user alice/login
otpme-tool sync
id alice

# Inspect the role.
otpme-role show management-user$
otpme-role list_tokens management-user
otpme-role list_users management-user
```

### Nested Roles

Roles can contain other roles. This is useful when you have multiple roles
(e.g. `management-user`, `marketing-user`) and want all of them to share a
common group membership via a single `staff` role:

```bash
# Remove the direct role-to-group assignment.
otpme-group remove_role staff management-user
otpme-tool sync
id alice

# Add a staff role.
otpme-role add staff
# Assign the staff role to the group.
otpme-group add_role staff staff
# Make management-user a member of the staff role.
otpme-role add_role staff management-user
```

Alice now belongs to the `staff` group because her `management-user` role is a
member of the `staff` role which is assigned to the `staff` group.

To also ensure that all management users are members of the `management` group,
add the role directly to that group as well:

```bash
otpme-group add_role management management-user
```

## 15. Units

Units are organisational containers for users, groups and other objects (tokens are bound to users, not to units).
They can be used to delegate administration — e.g. allowing department
executives to manage users within their own unit:

```bash
otpme-unit add management
otpme-unit add management/users
otpme-unit add management/groups

# Move user and group into the appropriate units.
otpme-user move alice management/users
otpme-group move management management/groups
```

## 16. Delegate Unit Administration

To allow a dedicated manager user to administer objects within a unit, create
the manager user inside the unit and grant them the necessary ACLs.

The `-r` flag on `add` replaces an existing token (useful when re-running
the setup). For easy testing the password is set to a fixed value here.

```bash
# Add management manager user joe.
otpme-user add management/users/joe
otpme-token --type password add -r joe/login
otpme-token -f --type password password joe/login password
```

Grant joe the right to create, delete and edit users and their tokens within
the `management/users` unit. The `+` prefix means the ACL is inherited within
the unit, `++` means it is inherited recursively into sub-units:

```bash
otpme-unit add_acl management/users token joe/login "add:user"
otpme-unit add_acl management/users token joe/login "delete:user"
otpme-unit add_acl management/users token joe/login "+user:edit"
otpme-unit add_acl management/users token joe/login "+user:enable"
otpme-unit add_acl management/users token joe/login "+user:disable"
otpme-unit add_acl management/users token joe/login "+user:add:attribute"
otpme-unit add_acl management/users token joe/login "+user:add:token"
otpme-unit add_acl management/users token joe/login "+user:delete:token"
otpme-unit add_acl management/users token joe/login "+user:delete"
otpme-unit add_acl management/users token joe/login "+token:edit"
otpme-unit add_acl management/users token joe/login "+token:enable"
otpme-unit add_acl management/users token joe/login "+token:disable"
```

Allow joe to set the default group of users to `management` and to
add/remove tokens from the `management-user` role:

```bash
# Allow joe to add/remove users to/from the management default group.
otpme-group add_acl management token joe/login "add:default_group_user"
otpme-group add_acl management token joe/login "remove:default_group_user"
# Allow joe to add/remove tokens from the management-user role.
otpme-role add_acl management-user token joe/login "add:token"
otpme-role add_acl management-user token joe/login "remove:token"
```

With these ACLs in place, joe can now add users to the unit and assign them
to the group and role directly at creation time using `--group` and `--role`:

```bash
# Login as joe and add a test user.
otpme-tool login joe
otpme-user add --group management --role management-user management/users/user1
otpme-token --type password add user1/wlan
otpme-tool logout
```

## 17. Simplify User Creation with Policies

Having to specify `--group` and `--role` on every `otpme-user add` call is
tedious. Policies can automate these assignments so that new users created
within a unit get the right group and role automatically.

First, create a unit for the policies:

```bash
otpme-unit add management/policies
```

### Default Groups Policy

Configure that new users in the `management/users` unit automatically get
`management` as their default group:

```bash
# Add default groups policy.
otpme-policy --type defaultgroups add management/policies/management-groups
# Configure that the default group of new users will be management.
otpme-policy --type defaultgroups default_group management-groups management
# Remove the existing default policy from the unit.
otpme-unit remove_policy management/users default_groups
# Add the new default groups policy to the unit.
otpme-unit add_policy management/users management-groups
```

### Default Roles Policy

Configure that new users in the unit are automatically added to the
`management-user` role:

```bash
# Add default roles policy.
otpme-policy --type defaultroles add management/policies/management-roles
# Configure that new users will be added to the management-user role.
otpme-policy --type defaultroles add_default_role management-roles management-user
# Remove the existing default policy from the unit.
otpme-unit remove_policy management/users default_roles
# Add the new default roles policy to the unit.
otpme-unit add_policy management/users management-roles
```

### Remove Object Templates Policy

If object templates are not needed, remove that policy from the unit:

```bash
otpme-unit remove_policy management/users object_templates
```

### Default Units Policy

To allow joe to add users without having to specify the target unit each
time, assign a `defaultunits` policy directly to joe:

```bash
# Add default units policy.
otpme-policy --type defaultunits add management/policies/management-units
# Set the default unit for new users.
otpme-policy --type defaultunits set_unit management-units user management/users
# Add the policy to user joe.
otpme-user add_policy joe management-units
```

Joe can now create users with a simple `otpme-user add <username>` and they
will automatically land in `management/users`, get `management` as their
default group and be assigned the `management-user` role.

## 18. Joining a Host to the Realm

Before a host can authenticate users via OTPme, it must be joined to the realm.
The join command must always be run as root on the host itself. It creates the
host object in the realm automatically.

```bash
otpme-tool join
```

### Joining as an Ordinary User

To allow a non-root user like joe to join hosts, grant the necessary ACLs on
the `JOIN` access group and the `hosts` unit:

```bash
otpme-accessgroup add_acl JOIN token joe/login "join:host"
otpme-accessgroup add_acl JOIN token joe/login "leave:host"
otpme-unit add_acl hosts token joe/login-piv "add:host"
```

Joe can then join a host on the host itself:

```bash
# First remove any existing host object.
otpme-tool leave            # run on the host
otpme-host del <yourhostname>   # run on a node
# Now join as joe.
otpme-tool -u joe join
```

### Joining via JOTP

An alternative is to pre-create the host object in the realm first. This is
useful when you want to let a user join one specific host without granting the
general right to join any host. When a host object is created, a JOTP
(join one-time password) is displayed. The host can then join using that JOTP:

```bash
# Remove existing host object and re-create it to get a fresh JOTP.
otpme-tool leave
otpme-host del <yourhostname>
otpme-host add <yourhostname>
# On the host, join using the JOTP. A LOTP is displayed which can be used to leave.
otpme-tool join --jotp <jotp>
```

### Allow Users to Log in to a Host

By default, login to a host is restricted: only tokens explicitly assigned to
the host (directly or via a role) are permitted, and only users with such
tokens are synced to the host. To allow joe to log in, assign his token:

```bash
otpme-host add_token <yourhostname> joe/login
```

Trigger a sync on the host and verify the user is available:

```bash
otpme-tool sync
id joe
otpme-tool login joe
```

### Unlimit Logins

To allow all realm users to log in and be synced to a host, remove the login
restriction entirely:

```bash
otpme-host unlimit_logins <yourhostname>
```

### Controlling Which Users Are Synced

Without unlimiting logins, there are several ways to control which users get
synced to a host:

```bash
# Add a specific user as a sync user directly on the host.
otpme-host add_sync_user <yourhostname> <username>

# Add sync users to a role — all role members will be synced to hosts
# that have the role assigned.
otpme-role add_sync_user management-user alice

# Use a dedicated sync group.
otpme-group add mysyncgroup
otpme-group add_sync_user mysyncgroup alice
otpme-host add_sync_group <yourhostname> mysyncgroup

# Finally enable sync groups for the host.
otpme-host enable_sync_groups <yourhostname>

# If you use sync groups you may want to disable sync-by-login-token.
otpme-host disable_sync_by_login_token <yourhostname>
```

## 19. Configure the PAM Module

To enable OTPme logins on a host, the PAM module must be deployed. Copy the
module and the OTPme PAM configuration files into place:

```bash
# Copy the PAM module.
cp /opt/otpme/lib/python3.11/site-packages/etc/otpme/deploy/pam/pam-python/pam_otpme.py \
    /lib/security/
# Copy OTPme PAM configuration files.
cp /opt/otpme/lib/python3.11/site-packages/etc/otpme/deploy/pam/otpme-* /etc/pam.d/
```

Then edit the PAM file for the service you want to protect (e.g.
`/etc/pam.d/login`). Comment out the default includes and add the OTPme ones:

```
# Comment out the default includes:
#@include common-auth
#@include common-account
#@include common-session

# Add OTPme includes:
@include otpme-auth
@include otpme-account
@include otpme-session
```

You should now be able to log in as user joe from any TTY. To test, use
`login` and monitor `/var/log/syslog` for details:

```bash
login joe
```

## 20. Offline Logins

Offline login support must be enabled per token. Once enabled, the token
credentials are cached locally after a successful online login and can be
used when the OTPme server is unreachable.

```bash
otpme-token enable_offline joe/login
```

With session keeping enabled, the login session is additionally cached and
automatically loaded into `otpme-agent` on the next offline login:

```bash
otpme-token enable_session_keep joe/login
```

After logging in online as joe, verify that the offline token was cached:

```bash
otpme-tool show_offline_token
```

For hosts with special security requirements, offline tokens can be pinned.
This ensures that only login with the pinned token is possible, preventing
even an administrator with server access from authorising a login with a
different token:

```bash
otpme-tool pin_offline_token
```

### Restrict Which Users May Log In

The following options in `/etc/otpme/otpme.conf` control which users are
allowed to log in to a specific host:

```
# Allow only the listed users to log in.
VALID_LOGIN_USERS="joe,alice"

# Allow all users except the listed ones.
DENY_LOGIN_USERS="alice"
```

## 21. Dynamic Groups

Dynamic groups allow OTPme to add users to local POSIX groups (via
`setgroups()`) at login time — for example to grant access to `plugdev` for
USB device handling. They can be configured on hosts, tokens and roles.

```bash
# Add all users that log in to this host to the plugdev group.
otpme-host add_dynamic_group <yourhostname> plugdev

# Add to plugdev for users authenticating with a specific token.
otpme-token add_dynamic_group joe/login plugdev

# Add to plugdev for all members of a role.
otpme-role add_dynamic_group management-user plugdev
```

For hosts with strict security requirements, dynamic group assignment can be
restricted in `/etc/otpme/otpme.conf`:

```
# Only allow assignment to the listed dynamic groups.
ALLOW_DYNAMIC_GROUPS="plugdev"

# Set to False to disable dynamic groups entirely on this host.
ALLOW_DYNAMIC_GROUPS="False"

# Leave empty to allow all dynamic groups except those listed in DENY_DYNAMIC_GROUPS.
ALLOW_DYNAMIC_GROUPS=""

# Block specific dynamic groups.
DENY_DYNAMIC_GROUPS="wheel"
```

## 22. Extending the Cluster

To achieve high availability and load balancing you can add more nodes to
the OTPme cluster. Install OTPme on the additional server (see README) and
run the join command with `--host-type node`:

```bash
otpme-tool join --host-type node
```

After joining, the new node starts syncing with the master node (check
`/var/log/otpme/otpme-clusterd.log`). To verify the cluster status:

```bash
otpme-cluster status
```

If the cluster is not fully in sync (indicated by coloured lines in the
output), use the `--diff` option to show the differences between nodes:

```bash
# Show object sync checksum differences.
otpme-cluster status --diff

# Compare full object data (may produce high load and take some time).
otpme-cluster status --diff --full

# Compare full index object data (may produce high load and take some time).
otpme-cluster status --diff --full-index
```

The OTPme cluster always has a master node which holds the floating IP
configured during `realm init`. All management commands are executed on the
master node. To failover the master role to another node, log in to the
target node and run:

```bash
otpme-cluster master_failover --wait
```

## 23. Fileserver and Shares

OTPme provides fileserver capabilities using FUSE mounts on the client side.
Files and directories in the share root (default: `/otpme-mounts/`, see
`otpme-site show_config <sitename> share_root`) must be available on all
cluster nodes — using CephFS is recommended, but a central NFS mount also
works.

### Share Scripts

When a new share is added, OTPme runs a configurable *add script*
(`otpme-site show_config <sitename> default_share_add_script`). The script
receives `$share_name`, `$share_root`, `$force_group`, `$force_create_mode`
and `$force_directory_mode` as environment variables and runs as the OTPme
system user (`otpme:otpme`), so `sudo(1)` may be needed for privileged
operations. Storing the actual script under `/otpme-mounts` makes it
available on all nodes.

```bash
# Edit the share add script (opens with $EDITOR).
otpme-script edit scripts/add_share.sh
```

There is also a *mount script*
(`otpme-site show_config <sitename> default_share_mount_script`) that runs
when a client mounts a share. It receives `$share_name` and `$share_root`:

```bash
# Edit the default mount script.
otpme-script edit scripts/mount_share.sh

# Override the mount script for a specific share.
otpme-share mount_script testshare scripts/mount_share_special.sh
```

To change the default scripts site-wide (can also be set per unit):

```bash
otpme-site config <sitename> default_share_add_script scripts/share_add_special.sh
otpme-site config <sitename> default_share_mount_script scripts/share_mount_special.sh
```

### Adding a Share

The share root directory must exist before creating the share (unless the
add script handles this):

```bash
mkdir /otpme-mounts/testshare
otpme-share add testshare
```

Shares support three *force* options that control ownership and permissions
for newly created files and directories:

```bash
otpme-share add \
    --force-group management \
    --force-directory-mode 0o770 \
    --force-create-mode 0o660 \
    testshare
```

These options can also be changed on an existing share:

```bash
otpme-share force_group testshare testgroup
otpme-share force_create_mode testshare 0o660
otpme-share force_directory_mode testshare 0o770
```

### Accessing a Share

To allow a user to access the share, add a token or a role:

```bash
otpme-share add_token testshare joe/login
```

To test share access, log in on a host or node and mount all shares. They
will appear under `/otpme/<site>/<share>`:

```bash
# Mount all shares.
otpme-mount -a

# Unmount all shares.
otpme-mount -a -u
```

To automatically mount shares when a user logs in via the PAM module, enable
auto-mount for the user:

```bash
otpme-user enable_auto_mount joe
```

### Encrypted Shares

OTPme supports encrypted shares where file content and path names are
encrypted on the client side. Every user who needs access to the share
(including the creating user) must have a public/private key pair:

```bash
otpme-user gen_keys root
otpme-user gen_keys joe
```

Create an encrypted share — you will be asked for a master password. Store
this password in a secure place, as it is needed to decrypt the share if the
last token is removed and no share keys are available any more:

```bash
otpme-share add --crypt testcrypt
```

### Using a Yubikey for Key Management

By default the private key created with `gen_keys` is encrypted by the key
script (`scripts/key_script.sh`) and stored in the user object on the nodes.
A more secure alternative is to use a Yubikey in PIV mode. The following
command replaces (`-r`) the user's default token so that the user can only
log in on hosts where the PAM module is configured and the Yubikey is
connected. The `--add-user-key` option adds the public key to the token
user:

```bash
# WARNING: This resets the PIV applet and erases all PIV keys on the Yubikey.
otpme-token --type yubikey_piv deploy --add-user-key -r joe/login

# To use a Yubikey that already has a private key configured, add -n:
otpme-token --type yubikey_piv deploy --add-user-key -n -r joe/login
```
