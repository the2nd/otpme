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
required. The example uses the realm `otpme.org`, site `munich` and a
floating cluster IP `192.168.1.100`:

```
$ORIGIN _tcp.munich.otpme.org.
_otpme-join    SRV 10 1 2024 login.munich.otpme.org.
_otpme-realm   TXT "otpme.org"
_otpme-site    TXT "munich"

$ORIGIN munich.otpme.org.
login          A   192.168.1.100
node1          A   192.168.1.1
node2          A   192.168.1.2
```

`node1`, `node2` etc. must match the hostnames and IPs of your actual nodes.

### Load balancing

For load-balanced authentication and login requests across multiple nodes, set
an auth FQDN for the site and add a round-robin DNS record for it:

```bash
otpme-site auth_fqdn munich auth.munich.otpme.org
```

```
$ORIGIN munich.otpme.org.
auth    A   192.168.1.1
        A   192.168.1.2
```

If you only have one site you can use the realm domain directly for all records
(e.g. `auth.otpme.org` instead of `auth.munich.otpme.org`).

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
    otpme.org munich login.otpme.org 192.168.1.100
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

## 4. Configure Management and SSO FQDNs

If you use OTPme with hosts and clients and have not initialized the realm
with `localhost`, you should configure the management and SSO FQDNs. Both
need DNS records pointing to the floating IP. The management FQDN is used
by `mgmtd` and `ldapd`; the SSO FQDN is used by `httpd` for the SSO
portal. The commands create the corresponding certificates automatically:

```bash
otpme-site mgmt_fqdn <site> <mgmt_fqdn>
otpme-site sso_fqdn <site> <sso_fqdn>
```

## 5. Configure WLAN Access

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

## 6. Add a User

```bash
otpme-user add alice
```

When a user is created, OTPme generates a default login token and displays its
QR code and PIN. This token is used for realm logins and group/role membership
(see later sections). You can display the user's full configuration at any time:

```bash
otpme-user show alice
```

## 7. Add a WLAN Token

Additional tokens can be created for specific services. The following creates a
password token with MS-CHAPv2 support (required by most RADIUS/WLAN setups):

```bash
otpme-token --type password add --enable-mschap alice/notebook-wlan
# Set a custom password if you don't want the generated one.
otpme-token --type password password alice/notebook-wlan
```

### Password Policy

A password or a PIN is checked when it is set. The check comes from the
password policy `password_strength`. A new site has it, and every user, token,
host and node gets it. A token without a password policy of its own is checked
with the one of its user.

The policy asks for at least 8 characters with a number, an uppercase and a
lowercase letter and a special character. A PIN must have at least 4 digits.
On top of these rules a strength checker gives the password a score from 0 to
10, and the score must be at least 2. The score is about the years it takes to
guess the password at a million tries a second. The checker also looks the
password up in the dictionaries the realm was created with (`--dicts`).

```bash
# Which policies the token has.
otpme-token list_policies alice/notebook-wlan
# The settings of the policy.
otpme-policy show password_strength
```

You can test a password against the policy without setting it. The output
shows the score and whether the password is strong enough:

```bash
otpme-policy --type password test --password "SuziMiller2019!" password_strength
```

To ask for longer passwords and PINs, change the policy:

```bash
otpme-policy --type password password_min_len password_strength 12
otpme-policy --type password pin_min_len password_strength 6
```

The score is an option of the strength checker. `strength_checker_opts` replaces
all options of the checker with what you give. An option you leave out goes
back to its default, and the default for the dictionaries is none. So give the
dictionaries again:

```bash
otpme-policy --type password strength_checker_opts password_strength \
	"min_score=3;dict_order=english,en-top10000,common-passwords,us-female,us-male,us-surnames,abbreviations-it"
```

The rules for numbers and letters can be switched on and off one by one, e.g.
`disable_require_special`. See `otpme-policy(1)`.

An admin can still set a password the policy refuses. This needs the ACL
`force_password`:

```bash
otpme-token --type password password --weak-password alice/notebook-wlan
```

## 8. Grant WLAN Access Directly via Token

The simplest way to grant access is to add the token directly to the access
group:

```bash
otpme-accessgroup add_token wlan alice/notebook-wlan
otpme-accessgroup list_tokens wlan

# Verify authentication.
otpme-auth verify --socket alice <password> ap01
```

## 9. Grant WLAN Access via Role (Recommended)

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

## 10. Restrict Login Times with Policies

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

## 11. Disable and Enable Users and Tokens

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

## 12. Login Failure Limits

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

## 13. Auto Disable

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

## 14. Groups

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

## 15. Role-Based Group Membership (Recommended)

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

## 16. Units

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

## 17. Delegate Unit Administration

To allow a dedicated manager user to administer objects within a unit, create
the manager user inside the unit and grant them the necessary ACLs.

The `-r` flag on `add` replaces an existing token (useful when re-running
the setup). For easy testing the password is set to a fixed value here.

```bash
# Add management manager user joe.
otpme-user add management/users/joe
otpme-token --type password add -r joe/login
otpme-token -f --type password password --weak-password joe/login password
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

### Log In Again Before an Action

When joe added the token, he was asked to log in again. That comes from the
policy `auth_on_action`. A new site has it, and every object gets it. Before
certain actions, e.g. adding a token, changing a PIN or deleting an object, it
asks the user to log in again with the token they are logged in with.

It does not ask over the local socket of a node, so root on a node is not
asked. It does not ask in API mode either.

```bash
otpme-policy show auth_on_action
```

`show` lists the actions it asks before (`HOOKS`), per object type. A login
again holds while the user keeps working: every action within
`reauth_timeout` (30 seconds by default) starts it anew. `reauth_expiry` is how
long it holds at most from the first login again, however busy the user is.
It is 0 by default, which means no limit. The timeout must be lower than the
expiry, so set the expiry first:

```bash
otpme-policy --type authonaction reauth_expiry auth_on_action 1h
otpme-policy --type authonaction reauth_timeout auth_on_action 5m
```

A timeout of 0 asks before every action.

Tokens and roles on the whitelist of the policy are never asked. A token in a
role counts, however deep the roles are nested:

```bash
otpme-policy --type authonaction whitelist_token auth_on_action joe/login
otpme-policy --type authonaction unwhitelist_token auth_on_action joe/login
# The same for a role.
otpme-policy --type authonaction whitelist_role auth_on_action <role>
```

You can also stop asking before a single action, and ask again. A hook you
removed by hand stays removed, also when an OTPme update brings new hooks
(`update_hooks`):

```bash
otpme-policy --type authonaction remove_hook auth_on_action user add_token
otpme-policy --type authonaction add_hook auth_on_action user add_token
```

The actions each object type knows are in the section AUTH ON ACTION HOOKS of
its man page, e.g. `otpme-user(1)`.

## 18. Simplify User Creation with Policies

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

### ID Range Policy

A new user gets a `uidNumber`, a new group a `gidNumber`. Both come from an
`idrange` policy. The site has `id_range` with the ranges given with
`--id-ranges` at realm init, here 70000-80000:

```bash
otpme-policy show id_range
```

A user or group added without a number gets the next free one from the policy
of its unit. If the unit has none, or none for that attribute, the policy of
the site counts. A unit further up does not count. A number given by hand must
lie in a range as well.

To give the users of the management unit a range of their own, add a policy
with a `uidNumber` range and assign it to the unit:

```bash
otpme-policy --type idrange add management/policies/management-ids
otpme-policy --type idrange add_id_range management-ids uidNumber:s:80001-89999
otpme-unit add_policy management/users management-ids
```

A range is written `<attribute>:<type>:<start>-<end>`. The attribute is
`uidNumber` or `gidNumber`. Type `s` hands out the numbers in order and goes on
after the last one it handed out. Type `r` takes a free number at random.
Ranges must not overlap with any range of any `idrange` policy, also not with
those of other sites.

The next user added to the unit gets the first free number of the new range:

```bash
otpme-user add management/users/user2
otpme-user show_ldif user2 -a uidNumber
```

Before a number is handed out, the policy checks that no user or group has it
already (`disable_id_check` turns that off). A range of type `s` goes on after
the last number it handed out. When that was the last number of the range, it
starts over from its start. When all numbers after the last one are taken,
e.g. because they were given by hand, no number is found and the user is not
added. With `enable_id_range_recheck` the policy then looks for gaps from the
start of the range, e.g. the numbers of deleted users:

```bash
otpme-policy --type idrange enable_id_range_recheck management-ids
```

### Token ACLs Policy

When joe added the token `user1/wlan`, the token got its ACLs from the policy
`token_acls`. A new site has it, and every user gets it. When a token is added
to the user, the policy gives three kinds of ACLs:

| Kind | Given on | Given to | Default |
|---|---|---|---|
| user ACLs | the user | the new token | `view_all`, `gen_keys`, `encrypt`, `decrypt`, `sign` |
| token ACLs | the new token | the token itself and the default token of the user | `view`, `edit:pin`, `edit:password`, `delete` |
| creator ACLs | the new token | the token that added it, when it belongs to another user (here `joe/login`) | `view`, `edit`, `delete` |

```bash
otpme-policy show token_acls
otpme-token list_acls user1/wlan
```

A token type can bring more ACLs of its own, and a token gets only the ones its
type knows. When a token is deleted, the same ACLs are taken away.

To allow users to disable their own tokens, e.g. when a notebook is lost, add
`disable` to the token ACLs. The user can then disable the token with their
default token:

```bash
otpme-policy --type tokenacls add_token_acl token_acls disable
```

A change to the policy counts for tokens added or deleted after it. Tokens
that exist already keep the ACLs they have. The commands for the other two
kinds are `add_user_acl` and `add_creator_acl`, and `del_...` takes an ACL away
again.

### Default Policies Policy

A new object gets its policies from the `defaultpolicies` policy of the unit
it is added to. A unit right below the site gets them from the site, and a
token from the unit of its user. A unit further up does not count.

The site has `default_policies` on the site and on every unit. It lists
policies per object type: `auth_on_action` for every type, `password_strength`
for users, tokens, hosts and nodes, `default_units` and `token_acls` for users,
and the default groups, roles and templates and itself for units. That is how
every new unit gets it as well.

```bash
otpme-policy show default_policies
```

To give the management users and their tokens a stricter password policy, add
a password policy:

```bash
otpme-policy --type password add management/policies/management-passwords
otpme-policy --type password password_min_len management-passwords 12
```

Changing `default_policies` would change it for every unit, and a unit takes
one policy of each type. So add a `defaultpolicies` policy for
`management/users` that lists what `default_policies` lists for users and
tokens, with the new password policy in place of `password_strength`. Tokens
need it too: a token gets a password policy of its own and is only checked with
the one of its user when it has none.

```bash
otpme-policy --type defaultpolicies add management/policies/management-defaults
otpme-policy --type defaultpolicies add_default_policy management-defaults user auth_on_action
otpme-policy --type defaultpolicies add_default_policy management-defaults user management-passwords
otpme-policy --type defaultpolicies add_default_policy management-defaults user default_units
otpme-policy --type defaultpolicies add_default_policy management-defaults user token_acls
otpme-policy --type defaultpolicies add_default_policy management-defaults token auth_on_action
otpme-policy --type defaultpolicies add_default_policy management-defaults token management-passwords
# Replace default_policies on the unit.
otpme-unit remove_policy management/users default_policies
otpme-unit add_policy management/users management-defaults
```

The next user added to the unit, and the tokens added to that user, get the new
password policy:

```bash
otpme-user add management/users/user3
otpme-user list_policies user3
otpme-token list_policies user3/login
```

A new object gets the listed policies without a check of rights. If one of them
cannot be assigned, the object is not added. Because of that, whoever adds a
policy to the list needs what assigning that policy needs. Objects that exist
already keep the policies they have.

## 19. Joining a Host to the Realm

Before a host can authenticate users via OTPme, it must be joined to the realm.
The join command must always be run as root on the host itself. It creates the
host object in the realm automatically.

```bash
otpme-tool join
```

### Joining as an Ordinary User

To allow a non-root user like joe to join hosts, add the token to the `JOIN`
access group and grant the necessary ACLs on the access group and the
`hosts` unit:

```bash
otpme-accessgroup add_token JOIN joe/login
otpme-accessgroup add_acl JOIN token joe/login "join:host"
otpme-accessgroup add_acl JOIN token joe/login "leave:host"
otpme-unit add_acl hosts token joe/login "add:host"
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

### Leaving via LOTP and Joining Again

The LOTP that the join printed lets the host leave the realm without a login.
Leaving revokes the certificate of the host and makes a new JOTP. The host
object stays. `otpme-host show` prints the JOTP, and the LOTP while the host is
joined.

```bash
# On the host.
otpme-tool leave --lotp <lotp>
# On a node: the new JOTP.
otpme-host show <yourhostname>
# On the host.
otpme-tool join --jotp <jotp>
```

By default only an admin sees the new JOTP. With `enable_jotp_rejoin`,
`otpme-tool leave` prints it, so whoever leaves the realm can join again
without an admin. When you turn it off, the printed JOTP stops working.
`gen_jotp` makes a new one, and the old one stops working.

```bash
otpme-host enable_jotp_rejoin <yourhostname>
otpme-host disable_jotp_rejoin <yourhostname>
otpme-host gen_jotp <yourhostname>
```

### A Lost Machine

If a notebook is lost or reinstalled, it has not left the realm. Disable the
host first, then make a JOTP for the new machine. `gen_jotp` refuses a host
that has joined and is still enabled. A join with `-f` takes the place of the
old machine: the certificate of the old one is revoked, and the host is
enabled again. Tokens, roles and sync users stay as they are.

```bash
otpme-host disable <yourhostname>
otpme-host gen_jotp <yourhostname>
# On the new machine.
otpme-tool join -f --jotp <jotp>
```

### Switching JOTP and LOTP Off

If a join or a leave should always need a login, switch the JOTP or the LOTP
off. When you switch one on again, it is printed. Nodes have the same commands
in `otpme-node`.

```bash
otpme-host disable_jotp <yourhostname>
otpme-host disable_lotp <yourhostname>
otpme-host enable_jotp <yourhostname>
otpme-host enable_lotp <yourhostname>
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

`limit_logins` goes back to how a host starts: only the tokens and roles
assigned to it may log in.

```bash
otpme-host limit_logins <yourhostname>
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

## 20. Configure the PAM Module

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

## 21. Offline Logins

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

## 22. Dynamic Groups

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

## 23. Extending the Cluster

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

### Who May Be Master: the Vote Script

The master role is not configured. The nodes of the site elect it again and
again, and the node that was last in sync with the master gets it. A vote
script lets a node take part in that decision. It runs on the node when its
vote is asked for. With it the node can say that it should not be master, for
example because it cannot reach the client network. The master holds the
floating IP, so a master that the clients cannot reach is of no use.

Every site has `scripts/node_vote_script.sh`, which only exits 0. Edit it
first. This version is happy if one of the listed addresses answers a ping:

```bash
otpme-script edit scripts/node_vote_script.sh
```

```bash
#!/bin/bash
for ip in 192.168.1.254 192.168.1.253; do
	ping -c 1 -W 1 -q "$ip" > /dev/null 2>&1 && exit 0
done
exit 1
```

Three things to keep in mind:

- List more than one address. If all nodes lose the ping, all of them vote
  that they cannot be master, and the site has no master.
- The script runs very often, in every round of the election. Keep the
  timeout short.
- It runs as the OTPme user, not as root. On Debian `ping` works without root.

The script is the same for all nodes. Set it for each node and start asking it:

```bash
otpme-node vote_script node1 scripts/node_vote_script.sh
otpme-node vote_script node2 scripts/node_vote_script.sh
otpme-node enable_vote_script node1
otpme-node enable_vote_script node2
```

An exit code of 0 keeps the normal vote of the node. Anything else votes 0, so
the node does not become master while the script says no. A master that votes
0 gives the role up. A script that is missing or fails to run votes 1. That is
lower than any sync time, so such a node is the last choice rather than no
choice, and the log says so.

`disable_vote_script` stops asking the script. The script stays set:

```bash
otpme-node disable_vote_script node2
```

## 24. Fileserver and Shares

OTPme provides fileserver capabilities using FUSE mounts on the client side.
Files and directories in the share root (default: `/otpme-mounts/`, see
`otpme-site show_config <sitename> share_root`) must be available on all
cluster nodes — using CephFS is recommended, but a central NFS mount also
works.

### Share Scripts

When a new share is added, OTPme runs a configurable *add script*
(`otpme-site show_config <sitename> default_share_add_script`). The script
receives `$share_name`, `$share_root`, `$force_group`, `$force_create_mode`
and `$force_directory_mode` as environment variables and runs as the
configured `ROOT_SCRIPT_USER`/`ROOT_SCRIPT_GROUP` (see `otpme.conf`), so
`sudo(1)` may be needed for privileged operations. Storing the actual
script under `/otpme-mounts` makes it available on all nodes.

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

A share can be made read-only, and it can be disabled entirely (which
refuses any new mount request — already mounted shares continue to work:

```bash
otpme-share enable_ro testshare
otpme-share disable testshare
```

### Share Notifications

OTPme supports share notifications via `idled`. Every online host connects
to `idled` on the master node on login, so it can react immediately when
share permissions change. To enable share notifications site-wide, set
the `send_share_notifications` config parameter:

```bash
otpme-site config <site> send_share_notifications True
```

With notifications enabled, re-enabling the share tells every logged-in
host or user to mount it; disabling it tells them to unmount it:

```bash
# Mounts the share on all currently logged in hosts/users.
otpme-share enable testshare

# Unmounts the share on all currently logged in hosts/users.
otpme-share disable testshare
```

The global `send_share_notifications` setting can be overridden per
command with `--no-share-notify`. You can additionally use
`--no-persist-mount` so that the mount or unmount does not persist on
hosts — for example, an offline login will then not re-mount the share:

```bash
# Disable but do not notify online hosts for this invocation.
otpme-share disable --no-share-notify testshare

# Enable but do not persist the mount on hosts.
otpme-share enable --no-persist-mount testshare
```

To see all logged in users and hosts, use the `who` command. By default
`who` is only allowed on nodes. To allow it from hosts too, set the site
config parameter `allow_who_from_hosts` to `True`:

```bash
otpme-tool who
```

### Limiting Share Access to Specific Hosts

Share access can be restricted to specific hosts or host groups. After
turning on host-based limiting with `limit_hosts`, only assigned hosts
(directly or via a host group) will be able to mount the share. Each
of the following commands also accepts `--share-notify`,
`--no-share-notify` and `--no-persist-mount`:

```bash
# Enable host-based access limiting on the share.
otpme-share limit_hosts testshare

# Limit to a single host.
otpme-share add_host testshare <yourhostname>

# Or use a host group.
otpme-group add testshare-hosts
otpme-group add_host testshare-hosts <yourhostname>
otpme-share add_group testshare testshare-hosts

# Or use a role. Adding hosts to roles is more flexible than host
# groups — you can, for example, add a role to another role.
otpme-role add testshare-hosts
otpme-role add_host testshare-hosts <yourhostname>
otpme-share add_role testshare testshare-hosts
```

### Choosing the Nodes That Serve a Share

By default a share is served by all nodes of its site. When a host mounts
a share it picks one of these nodes at random. If the node cannot be
reached, refuses the share or does not have the share root directory, the
host tries the next one. That is why every node of a share must hold the
same files under the share root (see the start of this chapter): OTPme does
not copy files from node to node.

If only some nodes should serve a share, for example only the nodes that
have the storage mounted, add them to the share. The first node you add
ends the "all nodes of the site" rule: from then on only the listed nodes
serve the share, and any other node refuses to mount it.

```bash
# Only node1 serves testshare now.
otpme-share add_node testshare node1

# Show the nodes of the share.
otpme-share list_nodes testshare

# Take the node off again. With no node left, all nodes serve the share.
otpme-share remove_node testshare node1
```

#### Pools

If many shares are served by the same nodes, add the nodes to a *pool*
instead of adding them to every share. A pool is a named list of nodes of
one site, and shares are the only thing pools are for. Add the pool to the
shares: its nodes serve them, and a node that you add to the pool later
serves all of these shares too.

```bash
# Add a pool. By default it goes into the unit "pools".
otpme-pool add storage

# Put nodes into the pool.
otpme-pool add_node storage node1
otpme-pool add_node storage node2

# Let the nodes of the pool serve the share.
otpme-share add_pool testshare storage

# Show the pools of the share.
otpme-share list_pools testshare
```

A share can have own nodes and pools at the same time. It is then served by
its own nodes and by the nodes of all its pools. `otpme-share list_nodes`
shows only the share's own nodes, not those of its pools; use
`otpme-pool list_nodes <pool>` for these.

A disabled pool gives no nodes to its shares, and a disabled node serves no
share. A share whose only pool is disabled, and that has no own nodes,
cannot be mounted until the pool is enabled again:

```bash
otpme-pool disable storage
otpme-pool enable storage
```

A host gets the list of nodes of a share when the user logs in, and again
with every mount. Hosts are not told when the nodes change. A mount on a
node that was taken off the share ends there, and the host switches to
another node from the list it has. So keep at least one node of the old
list on the share when you change its nodes or pools. If none is left,
users have to log in again to reach the share.

See `otpme-pool(1)` and the section "Pool and Node Management" in
`otpme-share(1)` for all commands.

### Encrypted Shares

OTPme supports encrypted shares where file content and path names are
encrypted on the client side. Every user who needs access to the share
(including the creating user) must have a public/private key pair.

> **Note:** Keys made with `gen_keys` are only meant to demonstrate and test
> OTPme. While they are used, the private keys are held unencrypted in memory
> and in otpme-agent. For real use we recommend a YubiKey in PIV mode, see
> *Using a Yubikey for Key Management* below: there the private key never
> leaves the key.

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
script (`scripts/key_script.sh`) and stored in the user object on the nodes,
but it is unencrypted in memory while it is used. A Yubikey in PIV mode is
the recommended way. The following
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

To use the Yubikey in PIV mode with the key script, configure the user's key
script options. The `--use-agent-piv` option delegates PIV operations to the
otpme-agent so you do not have to enter the PIV PIN on every operation:

```bash
otpme-user key_script joe scripts/key_script.sh -- --yubikey-piv AUTHENTICATION --use-agent-piv
```

To add the Yubikey PIV key to the ssh-agent on login via the PAM module,
configure the agent script with `--yubikey-piv`. By default the key is added
with confirmation enabled (ssh-askpass is called on each use). To disable
confirmation add `--no-confirm`:

```bash
otpme-user agent_script joe scripts/agent_script.sh -- --yubikey-piv --no-confirm
```

## 25. Encrypting, Decrypting and Signing Files

After logging in as a user with a key pair (see above), you can use
`otpme-tool` to encrypt, decrypt, sign and verify files:

```bash
# Create a test file.
echo test > test.txt

# Encrypt the file.
otpme-tool encrypt test.txt test.txt.enc

# Decrypt the file to stdout.
otpme-tool decrypt test.txt.enc /dev/stdout
```

Signing and verifying works similarly:

```bash
# Sign a file.
otpme-tool sign test.txt test.txt.sig

# Verify the signature.
otpme-tool verify test.txt.sig test.txt
```

### Encrypting for Another User and Key Modes

To encrypt a file for another user, give that user with `-u`. The file is
encrypted with their public key, so only they can decrypt it:

```bash
otpme-tool encrypt -u joe test.txt test.txt.enc
```

By default `gen_keys` makes the keys on the client, and the server gets the
private keys only encrypted with the key password of the user (key mode
`client`). With `--server` the server makes them and keeps the private keys
wrapped with a key that the client encrypts with the key password (key mode
`server`). Like `gen_keys` without it, this is only for testing; see the note
under *Encrypted Shares*.

```bash
otpme-user gen_keys --server joe
otpme-user get_key_mode joe
```

### Script Signature Verification

Signing can also be used to sign OTPme scripts such as the agent script. A
host can then be configured to verify script signatures before executing
them. To sign the agent script with the root user on the master node:

```bash
otpme-script sign scripts/agent_script.sh
```

On the host that should verify the agent script signature, add root as a
trusted signer. After this, the PAM module will verify the script signature
on login — if no valid signature from user root exists, the script will not
run:

```bash
otpme-tool add_signer --signer-type agent_script "user|realm/root"

# Show configured signers.
otpme-tool show_signer
```

### Token Signature Verification (SSH)

Besides scripts, it is also possible to sign tokens. Currently SSH tokens
are supported (note: YubiKey PIV tokens are also SSH tokens). This allows a
host to only accept SSH public keys that have been signed by a trusted user.

First, add an SSH token and assign it to the host:

```bash
# Add SSH token with the user's public key.
otpme-token --type ssh add joe/ssh "<ssh_public_key>"

# Add the token to the host.
otpme-host add_token <yourhostname> joe/ssh

# Trigger sync and verify the key is available.
otpme-tool sync
otpme-get-authorized-keys joe
```

Now add a token signer on the host. After this, only signed SSH keys will be
accepted:

```bash
# Add token signer (run on host as root).
otpme-tool add_signer --signer-type token "user|realm/root"
otpme-tool sync

# The SSH key should no longer be shown — it is not signed yet.
otpme-get-authorized-keys joe
```

Sign the SSH token on the master node, then sync again:

```bash
# Sign SSH token (run on master node).
otpme-token --type ssh sign joe/ssh

# Trigger sync on the host.
otpme-tool sync

# Now the SSH public key should be shown — it is signed by root.
otpme-get-authorized-keys joe
```

## 26. SSH Login Configuration

To allow SSH logins using OTPme-managed authorized keys, add the following
to your SSH configuration (e.g. `/etc/ssh/sshd_config.d/otpme.conf`):

```
AuthorizedKeysCommand /opt/otpme/bin/otpme-get-authorized-keys
AuthorizedKeysCommandUser root
PermitUserEnvironment yes
```

## 27. TOTP Login and Second Factor Authentication

If you do not have a hardware token or smartcard, you can use a TOTP token
with any TOTP authenticator app (e.g. Google Authenticator). Add a TOTP
token and scan the displayed QR code with your authenticator app:

```bash
# Add TOTP token.
otpme-token --type totp add joe/totp

# Allow realm logins with the TOTP token.
otpme-role add_token REALM_USER joe/totp

# Allow login to your host.
otpme-host add_token <yourhostname> joe/totp
```

After syncing (`otpme-tool sync` or waiting for `SYNC_INTERVAL` (default 180s, configurable in `/etc/otpme/otpme.conf`)), enter
PIN+OTP at the login prompt.

### Allow Only Certain Token Types

A `forcetoken` policy says which tokens may log in. It is checked at every
login on the role, host, node, client or access group it is assigned to, for
admin tokens too. A link token is checked as the token it points to.

The site has two of them, assigned to nothing:

| Policy | Pass types it lets in |
|---|---|
| `force_token_otp` | `otp` (hotp, totp, motp), `otp_push`, `tiqr` |
| `force_token_non_static` | the same, and `ssh_key` and `smartcard` (fido2, u2f, passkey, yubikey_hmac, yubikey_piv) |

To let only OTP tokens log in to your host:

```bash
otpme-policy show force_token_otp
otpme-host add_policy <yourhostname> force_token_otp
```

You can also add your own policy. It has two lists, and a token must match both
of them where they are set: its token type must be in `force_token_types`, and
its pass type in `force_pass_types`. A new policy has no token types and the
pass types `otp`, `otp_push`, `tiqr`, `ssh_key` and `smartcard`. To let in only
TOTP and FIDO2 tokens:

```bash
otpme-policy --type forcetoken add totp-fido2
otpme-policy --type forcetoken force_token_types totp-fido2 totp,fido2
```

Each command replaces its list, and `""` empties it, so it no longer limits
anything.

A password token is of the pass type `static`. Only with its second factor
enabled, as in the next section, it counts as `otp`, and `force_token_otp` lets
it in. Until then the policy refuses it, so remove the policy from the host
again for now:

```bash
otpme-host remove_policy <yourhostname> force_token_otp
```

### Using TOTP as Second Factor

For offline logins it is recommended to use a password token with the TOTP
token as second factor. This way the offline token/session data is encrypted
with the password+PIN, which is more secure than encrypting it with just the
TOTP PIN:

```bash
# Add password token.
otpme-token --type password add joe/pass

# Set TOTP token as second factor of the password token.
otpme-token --type password 2f_token joe/pass totp

# Enable second factor authentication.
otpme-token --type password enable_2f joe/pass

# Enable offline token and session keeping.
otpme-token enable_offline joe/pass
otpme-token enable_session_keep joe/pass

# Allow realm logins with the password token.
otpme-role add_token REALM_USER joe/pass
otpme-host add_token <yourhostname> joe/pass
```

Since the TOTP token is now used as a second factor of the password token,
the standalone TOTP permissions are no longer needed:

```bash
otpme-role remove_token REALM_USER joe/totp
otpme-host remove_token <yourhostname> joe/totp
```

After syncing (`otpme-tool sync` or waiting for `SYNC_INTERVAL` (default 180s, configurable in `/etc/otpme/otpme.conf`)), enter
password+PIN+OTP at the login prompt.

## 28. Confirmation Policy

OTPme asks for confirmation when changing or deleting objects. This
behaviour is controlled by the `confirmation_policy` config parameter:

- **paranoid** — ask for confirmation on all changes; deleting requires typing the object name (default)
- **normal** — only ask when deleting objects; requires typing the object name to confirm
- **force** — never ask for confirmation

The `-f` command line option also skips all confirmations regardless of the
policy.

The policy can be set on the site (applies globally), on a unit or on
individual tokens:

```bash
otpme-site config <site> confirmation_policy force
```

## 29. 802.1x and MAB Port Authentication

OTPme supports 802.1x and MAC Authentication Bypass (MAB) port
authentication. To use either method, configure your switch to send RADIUS
requests to the OTPme nodes.

Both MAB and 802.1x require an access group and a client for the switch:

```bash
# Create an access group for LAN access.
otpme-accessgroup add lan

# Add the switch as an OTPme client. If the switch sends a NAS-Identifier
# the client name must match it; otherwise use the switch IP.
otpme-client add switch1 192.168.1.20

# Assign the access group to the client.
otpme-client access_group switch1 lan
```

### MAB (MAC Authentication Bypass)

For MAB, add the host's MAC address to the host object and then add the
host to the access group. You can also add hosts to roles and roles to the
access group:

```bash
otpme-host mac <yourhostname> 90:1b:0e:46:46:15
otpme-accessgroup add_host lan <yourhostname>
```

You can define a default access group that new hosts are automatically
added to:

```bash
otpme-site config <site> hosts_accessgroup lan
```

### MAB for Network Devices (Printers etc.)

For non-host devices such as printers, use the `otpme-device`
command instead. You can also add devices to roles and roles to the access
group:

```bash
otpme-device add <devicename>
otpme-device mac <devicename> 90:1b:0e:46:46:16
otpme-accessgroup add_device lan <devicename>
```

Similarly to hosts, you can define a default access group for new devices:

```bash
otpme-site config <site> devices_accessgroup lan
```

### VLAN Assignment

VLANs are objects. Create one before you can assign it. The VLAN ID is
optional — switches configured with named VLANs (e.g. Cisco) get the VLAN
name instead:

```bash
# VLAN with an 802.1Q VLAN ID.
otpme-vlan add guests 100
# VLAN without an ID. The name "printers" is sent to the switch.
otpme-vlan add printers
```

To assign a VLAN, set the `vlans` config parameter. Where you set it
depends on the authentication method — for 802.1x it must be set on the
token, for MAB on the host or device:

```bash
# 802.1x: VLAN based on the authenticating token.
otpme-token config joe/login vlans guests
# MAB: VLAN based on the host or device.
otpme-host config <yourhostname> vlans guests
otpme-device config <devicename> vlans printers
```

Assigning a VLAN requires the `assign` ACL on the VLAN object. That way you
can let an operator hand out the guest VLAN without giving them access to
the server VLAN:

```bash
otpme-vlan add_acl guests role helpdesk assign
```

If your users live on the master site only while each site runs its own
VLANs, prefix the site name. The site owning the VLAN has to accept
assignments from the assigning site first — otherwise the VLAN is ignored
when that site answers the RADIUS request. Use `-a` to append a second
site's VLAN to the object rather than replacing the existing value:

`vlan_trusts` accepts entries in the following forms:

| Entry | Meaning |
|-------|---------|
| `berlin` | Objects of site `berlin` may get any VLAN. |
| `berlin:munich` | Objects of site `berlin` may get any VLAN of `munich`. |
| `berlin:munich/home` | Objects of site `berlin` may get only the VLAN `home` of `munich`. |
| `berlin:berlin/clients` | Objects of site `berlin` may get only the VLAN `clients` of `berlin`, which `munich` then switches in its own network. |

```bash
# On the site owning the VLAN:
otpme-site config munich vlan_trusts berlin
# On the assigning site, after the vlan_trusts change has synced
# (run `otpme-tool sync` to trigger a manual sync):
otpme-host config -a <yourhostname> vlans munich/guests
```

### 802.1x Authentication

For 802.1x you do not need to add the host to the access group. Instead,
add the user's token to the access group. Currently only `password` and
`yubikey_piv` tokens support 802.1x authentication:

```bash
otpme-accessgroup add_token lan joe/login
```

You also need to enable 802.1x authentication on the client:

```bash
otpme-client enable_dot1x switch1
```

On the host side, enable 802.1x in the PAM module configuration. The
relevant PAM options are:

- `do_dot1x=auto|force` — *auto* performs dot1x only when the default gateway is unreachable; *force* always performs dot1x on login (restarts the network connection)
- `dot1x_connection` — Network Manager connection to use for 802.1x (defaults to `dot1x-lan`)
- `dot1x_token_type` — token type used for 802.1x OTP generation (e.g. `yubikey_piv`, `password`)
- `dot1x_timeout` — seconds to wait for 802.1x authentication to complete

A typical PAM configuration line:

```
auth [success=1 default=ignore] pam_python.so pam_otpme.py try_first_pass \
    do_dot1x=force dot1x_token_type=yubikey_piv dot1x_timeout=10 \
    cache_login_tokens use_smartcard=auto use_ssh_agent=auto start_ssh_agent=auto \
    check_offline_pass_strength=password_strength;0:6,1:6,2:6,3:5,4:5,5:5,6:3,7:3,8:3,9:3,10:3
```

Before enabling dot1x, configure a Network Manager dummy connection on the
host. The user/password values are placeholders and will be set by the PAM
module on login. `ca-cert` and `domain-suffix-match` are required so the
supplicant validates the RADIUS server before sending credentials. All
OTPme nodes share the site certificate whose SAN is `<site>.<realm>`, so
one `domain-suffix-match` covers every RADIUS node:

```bash
nmcli connection add type ethernet con-name "dot1x-lan" ifname enp0s25 \
    802-1x.eap ttls \
    802-1x.phase2-auth pap \
    802-1x.ca-cert /etc/otpme/ssl/ca.pem \
    802-1x.domain-suffix-match <site>.<realm> \
    802-1x.anonymous-identity "anonymous@<realm>" \
    802-1x.identity "user" \
    802-1x.password "pass"
```

## 30. SSO Portal

OTPme comes with an SSO web portal. Users sign in there, see and manage
their own tokens and sessions, and web applications such as Nextcloud or
SOGo sign their users in through it — the portal is also the OpenID
Connect provider of the site.

The portal runs on every node of the site. Users reach it by the SSO FQDN
you set in chapter 4. That name points to the floating IP, so in practice
the master node answers.

### Who May Sign In: the SSO Access Group and the SSO Token

Who may sign in to the portal is decided by the access group `SSO`, like
every other login is decided by an access group. Every site has it, and the
role `SSO_USER` is in it. So a token in `SSO_USER` may sign in.

The token a user signs in with is the *SSO token*. Its name is the site
config parameter `default_sso_token_name`; the default is
`sso-<realm>-<site>`, here `sso-otpme.org-munich`. The name is what makes
a token the SSO token:

- the portal deploys and recovers this token,
- the tokens a user adds in the portal — passkeys, authenticator apps,
  tiqr phones — get its roles and access groups,
- `add_token` and `remove_token` of a role or access group ask whether
  the tokens the portal manages for the user should go along.

The SSO token has a name of its own, not the name of the default token
`login`. That keeps the realm login and the portal login apart: the user
can have a FIDO2 key for the portal and an OTP token for the hosts. With
several sites, each site has its own SSO token name, so one security key
can be registered at every portal.

There are two ways to give a user an SSO token.

#### You Add the SSO Token

Add a password token with the name of the SSO token. It is what gets the
user in the first time. With `enable_sso_deploy` the portal asks the user
at the first login to set up a real token — here a FIDO2 key. The new
token replaces the password token: it takes over its name and all its
roles and access groups.

```bash
# The password is printed. Hand it to the user.
otpme-token --type password add alice/sso-otpme.org-munich

# At the first login alice registers a FIDO2 key for herself.
otpme-token enable_sso_deploy alice/sso-otpme.org-munich fido2

# Allow the token to sign in to the portal.
otpme-role add_token SSO_USER alice/sso-otpme.org-munich
```

Because the token is the SSO token, `add_token` offers to add the tokens
the portal manages for alice as well: her security keys, passkeys,
authenticator apps and tiqr phones. This is the same for every role and
access group, and for `remove_token`. Answer yes, so all her portal
tokens get the same access. `--skip-portal-token` adds or removes the SSO
token alone. A token alice adds in the portal later gets the roles and
access groups of the SSO token by itself.

Without a type at `enable_sso_deploy` the user chooses one. Which types
are offered is decided by `sso_allow_fido2_deploy`, `sso_allow_totp_deploy`
(both on by default), `sso_allow_password_deploy` and
`sso_allow_tiqr_deploy` (both off by default).

#### The User Gets the SSO Token by the Account Recovery

You do not have to add the SSO token yourself. The login page of the
portal has a link "Can't sign in?". There a user enters their username.
OTPme looks up the recovery mail address of that user, the LDAP attribute
`otpmeRecoveryMail`, and sends a mail with a link to it. The link sets up a
new SSO token. The same way helps a user who lost their SSO token.

The page gives the same answer for every username, whether the user
exists and has a recovery mail address or not. So nobody can find out
with it which accounts there are.

For a user who has no SSO token yet, the portal creates one only where
`sso_token_deploy_roles` or `sso_token_deploy_accessgroups` is set. These
say which roles or access groups the new token is added to — `SSO_USER`,
so the user can sign in with it:

```bash
# Show the link on the login page.
otpme-site config <site> sso_show_recover_link True

# Allow the recovery, and the token types the user may choose.
otpme-site config <site> allow_sso_account_recovery True
otpme-site config <site> allow_sso_token_recovery fido2,totp

# Add the new token to the role SSO_USER.
otpme-site config <site> sso_token_deploy_roles SSO_USER
```

The mail is sent by the home site of the user, over the SMTP relay of the
site. Without a sender no mail is sent:

```bash
otpme-site config <site> sso_recovery_mail_from noreply@example.org
otpme-site config <site> smtp_relay_server mail.example.org
```

`smtp_relay_port`, `smtp_relay_starttls`, `smtp_relay_auth`,
`smtp_relay_username` and `smtp_relay_password` set the rest of the
connection.

##### The Recovery Mail

The text of the recovery mail is the *info text of the access group
`SSO`* of the site that sends it, one text per language. A new site writes
an English text there:

```bash
# Show the English text.
otpme-accessgroup dump_info --language en SSO
```

```
Account recovery

Hello,

we received a request to recover the SSO token for the account '{user_name}'.

To set up a fresh SSO token, open the following link within the next {minutes} minutes:

{reset_url}

If you did not request this, you can ignore this message -- your existing token stays untouched.
```

The first line is the subject, then comes an empty line, then the body.
These placeholders are filled in:

| Placeholder | Filled in with |
|-------------|----------------|
| `{user_name}` | the name of the user |
| `{minutes}` | how long the link works, from `sso_recovery_link_ttl` |
| `{reset_url}` | the recovery link |

A text with another placeholder is refused when you set it.

To change the text, or to add one for another language, run `info` with
the language. Without a text after the group name the command opens the
current text in your editor:

```bash
otpme-accessgroup info --language en SSO
otpme-accessgroup info --language de SSO
```

A user gets the text in their own language (`otpme-user language`), or
in the language their browser asks for when they have none. Where there
is no text for it, the English one is used, and where that is missing too,
the text OTPme brings, translated into the language of the user. A text
written without `--language` is the administrator's own note about the
access group and is never sent.

The mail goes to the recovery mail address of the user. Users can set it
themselves on the settings page of the portal, or you set it:

```bash
otpme-user add_attribute alice otpmeRecoveryMail=alice@example.org
```

`allow_sso_account_recovery`, `allow_sso_token_recovery`,
`sso_token_deploy_roles` and `sso_recovery_mail_from` can also be set on a
unit or a user, so the recovery can be allowed for some users only. A
link from the mail works for 15 minutes (`sso_recovery_link_ttl`).

#### Terms of Use

The portal can ask users to accept its terms of use before an SSO token is
set up for them. It then shows the terms with a box to tick, before the
user chooses a token type: at the deploy of the first login, at a
re-deploy from the settings page, and at an account recovery that creates
the SSO token. A recovery that replaces an SSO token does not ask.
Switch it on for the site, or for a unit or a single user:

```bash
otpme-site config <site> sso_confirm_terms True
```

The terms are the info text of the site, one text per language. The first
line of a text must be `Version: <version>`; a text without it, or an
empty one, is ignored as if there was none. A new site has an English
text with `Version: 1`:

```bash
otpme-site dump_info --language en <site>
```

```
Version: 1

Terms of use

Your SSO token is personal. Do not give it to anybody, and do not tell anybody its PIN or password.
Your device tokens, for example for WLAN access, are personal as well. You must not give them or their passwords to others.
If you lose a token, or think that somebody else knows its secret, tell your administrator at once.
Your logins are logged (time, address, application) to protect your account.
The terms can change. You will be asked again when they do.
```

To change it, or to add a text for another language, run `info` with the
language. Without a text after the site name the command opens the current
text in your editor:

```bash
otpme-site info --language en <site>
otpme-site info --language de <site>
```

A user gets the text in their own language, else the English one. If you
set a text without the version line, the command warns you, and the
portal goes on showing the English text.

The portal keeps on the user which version they accepted, with the time
and the language. It asks again only when the version changes. So fix a
typo without changing the version, and give the text a new version when
users have to accept a change:

```bash
# What alice accepted, per site of the portal.
otpme-user show_sso_terms alice

# Forget it, so the portal asks again at the next deploy.
otpme-user reset_sso_terms alice
```

A user of another site who signs in at this portal accepts the terms of
this site. Here only the value of `sso_confirm_terms` on the portal's site
counts. What the user accepted is kept on the user at their home site.

### Applications

A token in `SSO` may sign in to the portal, but that alone gets it into no
application. Every application has its own access group, and the token has
to be in it as well. So you decide per application who may use it.

The access group of an application has to be a *child group* of `SSO`. For
other access groups a child group means "the tokens of the parent get in
here too". `SSO` is the exception: the portal reads its child groups to
decide which applications it shows a user, and a token that is only in
`SSO` is still turned away by the application.

Here we add two applications, Nextcloud and SOGo:

```bash
# The access groups of the applications, under SSO.
otpme-accessgroup add nextcloud
otpme-accessgroup add_child_group SSO nextcloud
otpme-accessgroup add sogo
otpme-accessgroup add_child_group SSO sogo
```

#### Granting Access with Roles

Give access to the access groups of the applications with roles, not with
single tokens. Then a new application needs one step: add the role to its
access group, and every user in the role may use it. With single tokens
you would have to add the token of every user to every new access group.

**All portal users use the same applications.** Then you need no new role:
add the role `SSO_USER` to the access groups of the applications. Every
token that may sign in to the portal may then use them:

```bash
otpme-accessgroup add_role nextcloud SSO_USER
otpme-accessgroup add_role sogo SSO_USER
```

**Users need different applications.** Then add a role for each kind of
user. Put each role into `SSO_USER`, so its tokens may sign in to the
portal, and add it to the access groups of its applications. In this
example management users get Nextcloud and SOGo, marketing users get
Nextcloud only:

```bash
# Undo the example above: not every portal user gets every application.
otpme-accessgroup remove_role nextcloud SSO_USER
otpme-accessgroup remove_role sogo SSO_USER

# One role for each kind of user, inside SSO_USER.
otpme-role add management-sso-user
otpme-role add marketing-sso-user
otpme-role add_role SSO_USER management-sso-user
otpme-role add_role SSO_USER marketing-sso-user

# The applications of each role.
otpme-accessgroup add_role nextcloud management-sso-user
otpme-accessgroup add_role sogo management-sso-user
otpme-accessgroup add_role nextcloud marketing-sso-user
```

`otpme-role add_role SSO_USER management-sso-user` puts
`management-sso-user` into `SSO_USER`. Its tokens then reach everything
`SSO_USER` is assigned to — the access group `SSO`, and with it the portal —
plus what `management-sso-user` itself is assigned to.

Now put the SSO token of a user into the role for that user. It no longer
has to be in `SSO_USER` itself:

```bash
otpme-role remove_token SSO_USER alice/sso-otpme.org-munich
otpme-role add_token management-sso-user alice/sso-otpme.org-munich
```

When you add the SSO token, OTPme asks whether the tokens the portal
manages for the user should be added as well. Say yes, or alice cannot use
her passkey for Nextcloud.

#### Applications for Tokens from the Account Recovery

A new SSO token that the account recovery creates goes into the roles of
`sso_token_deploy_roles`. With roles per kind of user, set it on the unit
of those users, so they get the right role and with it the right
applications:

```bash
otpme-unit config management sso_token_deploy_roles management-sso-user
```

If you give access to an application directly, with the access group and
without a role, add the access group to `sso_token_deploy_accessgroups`
instead. Then a new SSO token from the recovery also lands in it:

```bash
otpme-site config <site> sso_token_deploy_accessgroups nextcloud
```

Both parameters hold a list, e.g. `nextcloud,sogo`, and both can be set on
the site, a unit or a user.

#### Example: Nextcloud with OpenID Connect

The portal is the OpenID Connect provider of the site. Nextcloud signs in
its users with the app `user_oidc`. First switch on the OIDC provider of
the site; this creates the key the tokens are signed with:

```bash
otpme-site enable_oidc <site>
```

Add a client for Nextcloud. `--enable-oidc` makes it an OIDC client and
gives it the default scopes of the site: `openid`, `profile` and `email`.
The client ID is the name of the client.

```bash
otpme-client add --enable-oidc nextcloud
otpme-client access_group nextcloud nextcloud
```

Register where Nextcloud gets the user back after the login and after the
logout, and where OTPme tells Nextcloud that the user signed out of the
portal. `otpme` at the end of the backchannel URL is the identifier you
give the provider in Nextcloud:

```bash
otpme-client add_oidc_redirect_uri nextcloud https://cloud.example.org/index.php/apps/user_oidc/code
otpme-client add_oidc_logout_redirect_uri nextcloud https://cloud.example.org/
otpme-client oidc_backchannel_logout_uri nextcloud https://cloud.example.org/index.php/apps/user_oidc/backchannel-logout/otpme
```

`user_oidc` reads the name, the mail address and the photo of the user from
the ID token and never asks `/userinfo`. By default OTPme puts these claims
into `/userinfo` only, so switch them on for this client:

```bash
otpme-client config nextcloud oidc_id_token_user_claims True
```

Print the client secret:

```bash
otpme-client show_secret nextcloud
```

On the Nextcloud server, register OTPme as a provider with the identifier
`otpme`, the client ID `nextcloud`, the secret and the discovery URL of
the site. You can do it on the admin page "OpenID Connect" of Nextcloud,
or with `occ`:

```bash
sudo -u www-data php occ user_oidc:provider otpme \
    --clientid=nextcloud \
    --clientsecret=<secret> \
    --discoveryuri=https://<sso_fqdn>/oidc/.well-known/openid-configuration \
    --scope="openid profile email"
```

Finally give Nextcloud a tile in the portal. The login URL starts the
login at Nextcloud; the number at the end is the ID Nextcloud gave the
provider (the first one is 1):

```bash
otpme-client login_url nextcloud https://cloud.example.org/index.php/apps/user_oidc/login/1
```

The tile shows the name of the client and no picture. Set the name users
should read and a logo:

```bash
otpme-client sso_name nextcloud "Nextcloud"
otpme-client sso_logo nextcloud /path/to/nextcloud.png
```

`otpme-client del_sso_logo nextcloud` removes the logo again.

An application that signs the user out sends them to the logout endpoint
of the portal (`/oidc/end_session`). What happens there is decided by the
config parameter `oidc_logout_scope`:

- `sso` (the default) signs the user out completely: the portal session
  ends, and with it every application session below it. Every application
  with a backchannel logout URI is told.
- `rp` ends only the session of this application. The user stays signed in
  to the portal and to the other applications.

Use `rp` for an application that should have its own, shorter session:

```bash
otpme-client config nextcloud oidc_logout_scope rp
```

The parameter can also be set on the site or a unit, as the default for
the clients below it.

What Nextcloud learns about the user is decided by the scopes. A scope is
granted only if the application asks for it, the client is in the scope
and the token of the user (or one of its roles) is in the scope. The three
default scopes already hold the role `SSO_USER`. For Nextcloud groups, use
the scope `groups` and add the client, the users and the groups Nextcloud
may see to it, see `otpme-scope(1)`. The OIDC parameters of a client, like
the lifetime of the access token or a consent screen, are in the section
"OIDC Provider" of `otpme(7)`, the commands in `otpme-client(1)`.

### Certificate

A new site makes a certificate for the SSO FQDN with its own CA. No browser
knows that CA, so for real use set a certificate of your own, together
with its key:

```bash
otpme-site sso_cert --key /path/to/key.pem <site> /path/to/fullchain.pem
```

Pass the full chain, not the certificate alone — with Let's Encrypt that
is `fullchain.pem`, not `cert.pem`. A browser usually copes with the
certificate alone, mobile apps do not, and they refuse to connect.

The portal takes the new pair when httpd is reloaded. Do this on every
node (and every SSO host, see below):

```bash
otpme-controld reload httpd
```

If certificate and key do not fit each other, the command says so, and the
portal keeps the pair it has. When you change the SSO FQDN later with
`otpme-site sso_fqdn`, a new certificate of the site CA replaces yours, so
set your own again afterwards.

### Logo

The portal shows the OTPme logo on its login and recovery pages. To show
your own, set a PNG or JPEG of at most 512 KiB. The tiqr app shows the
same logo:

```bash
otpme-site sso_logo <site> /path/to/logo.png

# Back to the OTPme logo.
otpme-site del_sso_logo <site>
```

### Running the Portal on a Host

A node has everything of its site and runs the portal as it is. A host
gets no keys or secrets of the site, so it cannot run the portal until you
make it an *SSO host*. Then it is synced the certificate and key of the
portal and the two secrets the portal signs its cookies and protects its
forms with:

```bash
otpme-site add_sso_host <site> <yourhostname>
```

On the host, set `SSO_SERVER` in `/etc/otpme/otpme.conf` and reload
controld. It then starts `otpme-httpd` on the host:

```bash
# /etc/otpme/otpme.conf
SSO_SERVER="True"
```

```bash
otpme-controld reload
```

`otpme-site remove_sso_host` takes the host off the list again.

An SSO host is typically placed in the DMZ, so the nodes do not have to be
reachable from the internet. That is safe because an SSO host, like any
host, holds no token secrets: it cannot check a login itself. It hands
every login to `authd` on the nodes, and everything else the portal needs —
sessions, OpenID Connect, passkey and tiqr logins — to `ssod`. So the
firewall has to allow connections from the SSO host to the nodes on these
ports, besides the ports every host needs:

| Daemon  | Port |
|---------|------|
| `authd` | 2020 |
| `ssod`  | 2029 |

The SSO host connects to the addresses of the auth FQDN of the site (see
`otpme-site auth_fqdn`), or to the floating IP if none is set.

#### Several SSO Hosts Behind a Load Balancer

You can run the portal on several SSO hosts and put them behind an HTTP or
TCP load balancer. All of them get the same secrets, so a session cookie
made by one host is valid on all others, and the state of a login in
progress is kept by `ssod` on the nodes. No sticky sessions are needed.

With an HTTP load balancer, the portal sees the address of the load
balancer instead of the client. Add the load balancer's IP to
`reverse_proxy_ips`. The portal then takes the client address from the
`X-Forwarded-For` header, for its logs and its rate limits. It trusts that
header only from the addresses listed there. If a second proxy stands in
front of the load balancer, add its address as well:

```bash
otpme-site config <site> reverse_proxy_ips 192.168.10.5
```

The rate limits of the portal are counted on each host, so behind a load
balancer with several hosts a client gets as many tries as there are
hosts.

### Device Tokens

Many devices cannot do a login with OTP, for example a phone in the WLAN
or a mail app. For these, users can add *device tokens* in the portal: a
separate password for each device. If a device is lost, the user deletes
its token and the other devices keep working.

The portal adds a device token to a role, and the role decides what the
token may do. Here we use the role `wlan-user` from chapter 9, which is in
the access group `wlan`, so a device token in it gets WLAN access.

A role is offered for device tokens only when it has the config parameter
`device_token_suffix`. The suffix is added to the token name with a `-`:
the device `iphone` becomes the token `iphone-wlan`.

```bash
otpme-role config wlan-user device_token_suffix wlan
```

WLAN with PEAP/MSCHAPv2 needs MSCHAP on the token. It is off by default,
because MSCHAP keeps the NT hash of the password on the server:

```bash
otpme-role config wlan-user device_token_mschap True
```

The portal shows the info text of the role, so users know what the role
is for. Only a text with a language is shown; the portal picks the one in
the language of the user. A text without a language is a note for
administrators and is never shown:

```bash
otpme-role info --language en wlan-user "A password for each device that uses the company WLAN."
otpme-role info --language de wlan-user "Ein Passwort pro Gerät für das Firmen-WLAN."
```

Finally offer the role to the users. Set `device_token_roles` on the site
for all users, or on a unit or a single user; the most specific value wins:

```bash
otpme-site config <site> device_token_roles wlan-user
```

More config parameters of the role:

- `device_token_types` — `password` (the default) and/or `totp`. With
  both, the user chooses for each token.
- `max_device_tokens` — how many device tokens a user may have in this
  role.

### Tokens Users Manage Themselves

On the settings page of the portal users can manage their own login
tokens of four types: FIDO2 security keys, passkeys, authenticator apps
(TOTP) and tiqr phones. A token a user adds there gets the roles and
access groups of their SSO token, so it reaches the same applications.

Each type has three config parameters, on the site, a unit or a user:

| Type | May be used at all | Users manage their own | Limit per user |
|------|--------------------|------------------------|----------------|
| FIDO2 security key | `sso_allow_fido2` | `sso_allow_fido2_mgmt` | `sso_max_fido2_token` |
| Passkey | `sso_allow_passkeys` | `sso_allow_passkey_mgmt` | `sso_max_passkey_token` |
| Authenticator app | `sso_allow_totp` | `sso_allow_totp_mgmt` | `sso_max_totp_token` |
| tiqr phone | `sso_allow_tiqr` | `sso_allow_tiqr_mgmt` | `sso_max_tiqr_token` |

- *May be used at all* covers signing in with the type and its card on the
  settings page. It is on by default; only an explicit `False` switches the
  type off.
- *Users manage their own* lets users list, add, enable, disable and
  delete their tokens of that type. It is off by default: which
  credentials users may add or remove on their own is your decision.
  Signing in with a token that exists is not affected.
- *Limit per user* is unset by default, which means no limit. Tokens an
  administrator adds are not counted against it.

```bash
otpme-site config <site> sso_allow_fido2_mgmt True
otpme-site config <site> sso_allow_passkey_mgmt True
otpme-site config <site> sso_allow_totp_mgmt True
otpme-site config <site> sso_allow_tiqr_mgmt True

# At most three security keys per user.
otpme-site config <site> sso_max_fido2_token 3
```

Some notes on the types:

- **FIDO2** keys are registered for a Relying Party ID, by default the
  realm name (`force_fido2_rp realm`). A browser hands out a credential
  only when the RP ID is the FQDN of the page or a domain above it, so this
  works only when the SSO FQDN is below the realm name, e.g.
  `sso.otpme.org` for the realm `otpme.org`. Otherwise register keys for
  the SSO FQDN. The setting applies to keys registered from then on:

  ```bash
  otpme-site config <site> force_fido2_rp sso_fqdn
  ```

- **FIDO2 keys of a known maker:** A FIDO2 key carries an attestation
  certificate that says who made it. With `check_fido2_attestation_cert`
  on (site, unit, user or token), a key is only taken when that certificate
  is valid and was signed by a CA certificate of the site. Only the CA that
  signed the key counts, not a root above it. The check is made when a key
  is deployed; keys that are deployed stay as they are.

  For YubiKeys you need two roots for older keys and the intermediates for
  firmware 5.7.4 and later. Yubico has the intermediates in one file, and
  `add_fido2_ca_cert` adds every certificate in it. That file also holds
  the CAs of the other functions of a YubiKey (PIV, OpenPGP and more).
  Remove those again: each CA on the site is one it trusts to say that a
  key is a FIDO2 key.

  ```bash
  wget https://developers.yubico.com/PKI/yubico-fido-ca-1.pem
  wget https://developers.yubico.com/PKI/yubico-fido-ca-2.pem
  wget https://developers.yubico.com/PKI/yubico-intermediate.pem
  otpme-site add_fido2_ca_cert <site> yubico-fido-ca-1.pem
  otpme-site add_fido2_ca_cert <site> yubico-fido-ca-2.pem
  otpme-site add_fido2_ca_cert <site> yubico-intermediate.pem
  # Keep only the FIDO ones.
  otpme-site list_fido2_ca_certs <site> | grep -v -e FIDO -e U2F | while read subject; do
      otpme-site -f del_fido2_ca_cert <site> "$subject"
  done
  otpme-site list_fido2_ca_certs <site>
  otpme-site config <site> check_fido2_attestation_cert True
  ```

  Without a CA for the maker of a key, that key is refused once the check
  is on.

- **Passkeys** are always registered for the SSO FQDN of the site.
- **tiqr** needs the tiqr app on the phone, and the phone has to trust the
  certificate of the portal — set the full chain, see *Certificate* above.
  The app shows the account under `tiqr_service_display_name` (default: the
  realm name) and with the logo of the site. The tiqr secret of the site
  is made with the site; `otpme-site tiqr_secret` makes a new one.

  ```bash
  otpme-site config <site> tiqr_service_display_name OTPme
  ```

The login page shows the buttons *Security Key* and *Sign in with tiqr*.
If you do not use one of them, hide it with the site parameter
`sso_show_fido2_button` or `sso_show_tiqr_button`.

For users of other sites the TOTP, passkey and tiqr cards need trust
entries, see *Users of Other Sites* below.

### What Users May Do in the Portal

Some more functions of the portal are off by default and have to be
switched on with a config parameter on the site, a unit or a user. For
example:

```bash
# Users see their own sessions and can end them.
otpme-site config <site> sso_allow_session_mgmt True

# Users may change these LDAP attributes on their profile page.
otpme-site config <site> sso_allow_profile_edit mail,telephoneNumber,mobile
```

Which token types a user may choose for a new SSO token, at the first
login and in the recovery, is decided by the `sso_allow_*_deploy`
parameters, see above. To leave TOTP tokens to the administrator:

```bash
otpme-site config <site> sso_allow_totp_deploy False
```

### Users of Other Sites

A user can sign in at the portal of another site of the realm. The portal
of `munich` then works with a user whose home site is `berlin`. What the
portal may do for such a user is decided by *trust lists* on the sites.
Without an entry a user of another site gets nothing there. Users of the
own site need no entry.

| Parameter | Set on | Allows |
|-----------|--------|--------|
| `device_token_roles_trusts` | portal site | device tokens in roles of the portal site |
| `sso_token_deploy_trusts` | portal site | a new SSO token in roles or access groups of the portal site |
| `sso_allow_passkeys_trusts` | both sites | passkeys of users of other sites |
| `sso_allow_totp_trusts` | both sites | authenticator apps of users of other sites |
| `sso_allow_tiqr_trusts` | both sites | tiqr phones of users of other sites |
| `admin_access_trusts` | home site | the admin access (temporary password) at the portal of another site |

The first two are set on the portal site and have two kinds of entries:

- the bare site, e.g. `berlin`: the users of `berlin` may get roles
  (or access groups) of this site at all;
- one entry for each role or access group, e.g. `berlin:wlan-user`. In
  front of the colon is the home site of the users, after it a role of the
  portal site — the site the parameter is set on. So `berlin:wlan-user` on
  `munich` means "users of `berlin` may get `munich`'s role `wlan-user`".
  For `sso_token_deploy_trusts` the type is part of the entry:
  `berlin:role/SSO_USER` or `berlin:accessgroup/nextcloud`.

Both are needed. On `munich`, users of `berlin` get device tokens in the
role `wlan-user`, and new SSO tokens in the role `SSO_USER`:

```bash
otpme-site config munich device_token_roles_trusts berlin,berlin:wlan-user
otpme-site config munich sso_token_deploy_trusts berlin,berlin:role/SSO_USER
```

The bare site entry is the general permission. Without it no role entry of
that site counts. So to suspend a site for a while, remove only the bare
entry; the role entries stay and count again as soon as you put it back:

```bash
otpme-site config munich device_token_roles_trusts berlin:wlan-user
```

For `sso_token_deploy_trusts` a suspended site means: the recovery still
creates the new SSO token, but it gets into no role or access group of
`munich`, so the user cannot sign in with it. The portal logs a warning.

The passkey, TOTP and tiqr lists have to be set on both sites, because each
side protects something of its own. The portal site protects its backend
and access groups: a token added there gives the user a new way in. The
home site protects the secrets of its users: they are shown by the portal
site, so whoever controls that site could capture them. On the portal site
the list names the home sites of the users, on the home site the portal
sites:

```bash
otpme-site config munich sso_allow_totp_trusts berlin
otpme-site config berlin sso_allow_totp_trusts munich
```

`admin_access_trusts` is set on the home site of the users and names the
portal sites where their admin access may be shown and changed:

```bash
otpme-site config berlin admin_access_trusts munich
```

The section "SSO Portal" in `otpme(7)` lists all parameters of the portal,
and the section "SSO Configuration" in `otpme-site(1)` the commands.

## 31. Trash

OTPme includes a trash that keeps deleted objects. Every object deleted via
a tree command (e.g. `otpme-user del`) is moved to the trash instead of
being permanently removed:

```bash
# Add and delete a test user.
otpme-user add user1
otpme-user del user1

# Show trash contents — user1 and its token are now in trash.
otpme-trash show
```

Objects can be restored by their trash ID:

```bash
# Restore object from trash.
otpme-trash restore <trash_id>

# Restore but keep a copy in the trash.
otpme-trash restore --keep <trash_id>

# Restore only specific objects from a trash entry.
otpme-trash restore --objects "user|realm/site/users/user1" <trash_id>

# Dump object data to inspect before restoring.
otpme-trash dump <trash_id> "user|realm/site/users/user1"
```

To permanently remove all objects from the trash:

```bash
otpme-trash empty
```

## 32. Backup and Restore

OTPme includes a backup tool that exports all OTPme data (excluding trash)
to a given directory. Additionally you must back up `/etc/otpme` to make a
full restore possible:

```bash
otpme-tool backup -d /var/backups/otpme
```

To perform a disaster recovery, make sure `/etc/otpme` is restored first,
then run:

```bash
otpme-tool restore -d /var/backups/otpme/<snapshot>
```

If you only need to restore a single object, specify the backup file
directly:

```bash
otpme-tool restore -f /var/backups/otpme/<snapshot>/user/realm+user1.json
```

## 33. Integrated Deduplication Backup Service

OTPme includes a built-in deduplication backup service. Any node or host
can act as the backup server. There are two backup modes:

- **pack** — backup data (chunks) is written to pack files of approximately 512 MB each. File and directory metadata is stored in an SQLite database. This is the default for nodes and more space-efficient.
- **tree** — in addition to pack files, the full directory tree including files is stored on the backup server. This allows mounting the backup repository from any host (e.g. via a restore share). This is the default for shares.

### Backup Server Configuration

On the host that will act as backup server, add the following settings to
`/etc/otpme/otpme.conf` and restart the daemons (`otpme-controld restart`):

```
# Enable the backup service on this host.
BACKUP_SERVER="True"
# Root directory for all backup repositories.
BACKUP_DIR="/var/backups"
# Allow new repositories from these client certificate CNs (comma-separated, or False).
ALLOW_NEW_BACKUP_REPOS="node1.site.realm,node2.site.realm"
```

### Backup Configuration Parameters

On the master node, all backup settings are managed via config parameters.
They can be set on sites, units, nodes, and shares (unless noted otherwise):

| Parameter | Description |
|---|---|
| `backup_enabled` | Enable or disable backups (`True`/`False`) |
| `backup_interval` | Backup interval (e.g. `1D`, defaults to 24h) |
| `backup_key` | AES backup key (64-character hex string; auto-generated if not set) |
| `backup_repo_password` | Repository password |
| `backup_script` | OTPme backup script (e.g. `scripts/backup_script.sh`) |
| `backup_server` | Backup node or host name (e.g. `backup-host`) |
| `backup_time` | Time window for starting backups (e.g. `22:00-05:00`) |
| `backup_excludes` | Directories/files to exclude (nodes and shares only) |
| `backup_includes` | Directories/files to include (nodes and shares only) |
| `backup_exclude_special` | Exclude special files such as device files |
| `backup_mode` | `pack` or `tree` (nodes and shares only) |

```bash
# Enable backup for all nodes and shares.
otpme-site config <site> backup_enabled True
# Set backup time window.
otpme-site config <site> backup_time "22:00-05:00"
# Set backup interval.
otpme-site config <site> backup_interval 1D
# Add an extra backup exclude for a specific node.
otpme-node config -a <node> backup_excludes some/dir
# Generate a site-wide backup key.
otpme-site config <site> backup_key
# Set backup server.
otpme-site config <site> backup_server backup-host
```

### Running Backups

You can test a backup in dry-run mode before running it for real:

```bash
# Dry run for a node.
otpme-backup start --dry-run node:node1
# Dry run for a share.
otpme-backup start --dry-run share:testshare
# Start backup with debug output to see progress.
otpme-backup -dd start node:node1
```

### Listing and Restoring Backups

```bash
# List available snapshots.
otpme-backup list node:node1
# List contents of a snapshot.
otpme-backup ls node:node1 2026-04-03T23-00-26 usr/bin
# Restore a specific path from a snapshot.
otpme-backup -dd restore --snapshot 2026-04-03T23-00-26 --path usr/bin --destination /tmp/restore node:node1
```

### Restore Shares

When a share has been backed up in tree mode, you can create a restore
share that allows mounting the backup repository on any host — including
for encrypted shares:

```bash
otpme-share add --restore testshare --restore-token joe/login testshare-restore
```
