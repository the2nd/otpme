# Getting Started with OTPme

This guide walks through the initial setup of an OTPme realm and explains
common day-to-day administration tasks using a practical example.

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
otpme-group show staff
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
otpme-role show management-user
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

Units are organisational containers for users, groups, tokens and other objects.
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
