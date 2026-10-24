# NAME

otpme-acls - the ACLs of the OTPme object types

# DESCRIPTION

What an ACL is, how it is written and how it is passed on is in
**otpme**(7), section **ACCESS CONTROL**. This page is the list: which
ACLs each kind of object knows.

An object tells you the same itself. **list_acls** shows the ACLs an
object has, and after **add_acl** the shell completion offers the ones
it takes:

> **otpme-user list_acls *alice***

This page is generated from the code, so it is what this version
supports.

# HOW TO READ THIS PAGE

A permission is the heading, what it applies to stands under it. Under
**view** the entry **tokens** means the ACL **view:tokens**. Under
**Alone** stand the permissions that take nothing after them.

A permission without a value covers all of its values: **edit** allows
every **edit:x**. **all** allows everything. **view_all** covers
**view** and **view_public**, and **view** covers **view_public**.

Two entries stand for a list of their own:

**attribute:\<name\>**  
One ACL per LDAP attribute of the object, for example
**edit:attribute:mail**. Which attributes an object has depends on the
extensions it has. The permission without the attribute
(**edit:attribute**) covers all of them.

**config:\<parameter\>**  
One ACL per config parameter of that object type, for example
**set:config:allow_temp_passwords**. **show_config** lists the
parameters of an object. The permission without the parameter
(**set:config**) covers all of them.

# THE ACLS OF EVERY OBJECT

Every kind of object has these. The list of an object type below names
only what it has on top of them.

**add**  
Every add:x of the object.

**all**  
Everything. Every permission of the object, also the ones a later
version adds.

**delete**  
Every delete:x of the object, and so the object itself.

**disable**  
Every disable:x of the object.

**edit**  
Every edit:x of the object.

**enable**  
Every enable:x of the object.

**export**  
Write the object out (export).

**import**  
Reserved. Reading an object in needs admin rights, the ACL is not asked
for.

**move**  
Move the object to another unit.

**remove**  
Every remove:x of the object.

**rename**  
Rename the object, the same as rename:object.

**set**  
Every set:x of the object.

**touch**  
Write the object again without changing it. Builds its index, its ACLs
and its LDIF again.

**verify_signature**  
Check the signatures of the object. Its own permission, so it can be
given without view.

**view**  
The normal data of an object. Covers view_public.

**view_all**  
All data, also the private ones like a certificate key. Covers view and
view_public.

**view_public**  
The public data of an object, what LDAP or getent(1) show without a
login.

**add:acl**  
Add an ACL (add_acl).

**add:attribute**  
Add an LDIF attribute.

**add:extension**  
Add an extension, which is what brings the LDAP attributes.

**assign:policy**  
Assign a policy.

**clear:changelog**  
Empty the changelog. Needs the config parameter allow_changelog_clearing
as well.

**delete:acl**  
Remove an ACL (del_acl).

**delete:attribute**  
Remove an LDIF attribute.

**delete:object**  
Delete the object.

**disable:acl_inheritance**  
Stop the object from taking the default ACLs of its unit.

**edit:attribute**  
Change an LDIF attribute.

**edit:changelog**  
Change the comment of a changelog entry.

**edit:description**  
Change the description.

**edit:info**  
Change the free text info of the object.

**enable:acl_inheritance**  
Let the object take the default ACLs of its unit again.

**remove:extension**  
Remove an extension.

**remove:orphans**  
Remove references to objects that are gone.

**remove:policy**  
Remove a policy. A plain remove does not cover it.

**rename:object**  
Rename the object.

**set:config**  
Change every config parameter of the object.

**set:config:\<parameter\>**  
Change one config parameter.

**view:acl_inheritance**  
See whether the object takes the default ACLs of its unit.

**view:attribute**  
See the LDIF attributes.

**view:changelog**  
See the changelog.

**view:checksum**  
See the checksum of the object.

**view:config**  
See every config parameter.

**view:config:\<parameter\>**  
See one config parameter.

**view:create_time**  
See when the object was created.

**view:creator**  
See who created it.

**view:description**  
See the description.

**view:extension**  
See the extensions of the object.

**view:full_oid**  
See the full OID, with realm and site.

**view:info**  
See the free text info.

**view:last_modified**  
See when it was changed last.

**view:last_used**  
See when it was used last.

**view:object**  
See the object at all. Without it the object is not there for the token.

**view:path**  
See the path in the tree.

**view:policies**  
See the policies of the object.

**view:read_oid**  
See the short OID.

**view:rel_path**  
See the path below the site.

**view:resolver**  
See which resolver the object comes from.

**view:resolver_checksum**  
See the checksum of the resolver data.

**view:resolver_key**  
See the key the resolver knows it by.

**view:sync_checksum**  
See the checksum the sync works with.

**view:uuid**  
See the UUID.

# THE ACLS PER OBJECT TYPE

## accessgroup

**add**  
child_group, child_session, device, host, role, token

**disable**  
force_sotp_signing, object, sessions, sotp_signing, timeout_pass_on

**edit**  
max_fail, max_fail_reset, max_sessions, relogin_timeout,
session_timeout, sign_public_keys, unused_session_timeout

**enable**  
force_sotp_signing, object, sessions, sotp_signing, timeout_pass_on

**join**  
host, node

**leave**  
host, node

**remove**  
child_group, child_session, device, host, role, token

**view**  
child_groups, child_sessions, devices, force_sotp_signing, hosts,
max_fail, max_fail_reset, max_sessions, relogin_timeout, roles,
session_timeout, sessions_enabled, sotp_signing, status,
timeout_pass_on, tokens, unused_session_timeout

## ca

**Alone**  
create_ca_cert, create_cert, create_client_cert, create_host_cert,
create_node_cert, create_server_cert, renew, revoke, update_crl

**disable**  
object

**edit**  
crl_validity

**enable**  
object

**renew**  
cert

**revoke**  
cert

**view**  
cert, country, crl, email, key, locality, organization, ou, state,
status

## client

**Alone**  
limit_logins, unlimit_logins

**add**  
address, oidc_grant_type, oidc_logout_redirect_uri, oidc_redirect_uri,
oidc_response_type, role, sso_logo, token

**delete**  
address, oidc_grant_type, oidc_logout_redirect_uri, oidc_redirect_uri,
oidc_response_type, sso_logo

**disable**  
auth_cache, dot1x_auth, object, oidc_auth, oidc_backchannel_tls_verify,
oidc_force_backchannel_logout, sso, sso_popup

**dump**  
sso_logo

**edit**  
accessgroup, auth_cache_timeout, helper_url, login_url,
oidc_auth_method, oidc_backchannel_ca_cert, oidc_backchannel_logout_uri,
oidc_id_token_alg, oidc_sector_identifier_uri, oidc_subject_type,
secret, sso_name

**enable**  
auth_cache, dot1x_auth, object, oidc_auth, oidc_backchannel_tls_verify,
oidc_force_backchannel_logout, sso, sso_popup

**find**  
scopes

**remove**  
role, token

**view**  
accessgroups, address, auth_cache, auth_cache_timeout, dot1x_auth,
helper_url, login_url, logins_limited, oidc_auth, oidc_auth_method,
oidc_backchannel_ca_cert, oidc_backchannel_logout_uri,
oidc_backchannel_tls_verify, oidc_force_backchannel_logout,
oidc_grant_types, oidc_id_token_alg, oidc_logout_redirect_uris,
oidc_redirect_uris, oidc_response_types, oidc_sector_identifier_uri,
oidc_subject_type, roles, scopes, secret, sso_enabled, sso_name,
sso_popup, status, tokens

## device

**disable**  
object

**edit**  
auto_disable, mac_address

**enable**  
object

**find**  
accessgroups, roles

**view**  
accessgroups, auto_disable, mac_address, roles, status

## dictionary

**Alone**  
dump

**add**  
dictionary, words

**delete**  
dictionary, words

**disable**  
object

**enable**  
object

**view**  
dictionaries, status

## group

**add**  
attribute:\<name\>, default_group_user, host, role, sync_user, token

**delete**  
attribute:\<name\>

**disable**  
object

**edit**  
attribute:\<name\>

**enable**  
object

**find**  
scopes, shares

**remove**  
default_group_user, host, role, sync_user, token

**view**  
attribute:\<name\>, hosts, roles, status, sync_users, tokens

## host

**Alone**  
join, leave, limit_logins, unlimit_logins

**add**  
attribute:\<name\>, dynamic_group, group, role, sync_group, sync_user,
token

**delete**  
attribute:\<name\>

**disable**  
jotp, jotp_rejoin, lotp, object, sync_by_login_token, sync_groups

**edit**  
attribute:\<name\>, auto_disable, mac, public_key

**enable**  
jotp, jotp_rejoin, lotp, object, sync_by_login_token, sync_groups

**find**  
accessgroups, groups, roles, shares

**remove**  
dynamic_group, group, role, sync_group, sync_user, token

**renew**  
cert

**revoke**  
cert

**view**  
accessgroups, attribute:\<name\>, auto_disable, cert, dynamic_groups,
groups, jotp, jotp_rejoin, key, logins_limited, lotp, mac, roles,
status, sync_groups, sync_users, tokens

## node

**Alone**  
join, leave, limit_logins, unlimit_logins

**add**  
attribute:\<name\>, dynamic_group, group, role, token

**delete**  
attribute:\<name\>

**disable**  
jotp, jotp_rejoin, lotp, object, vote_script

**edit**  
attribute:\<name\>, public_key, vote_script

**enable**  
jotp, jotp_rejoin, lotp, object, vote_script

**find**  
pools, shares

**remove**  
dynamic_group, group, role, token

**renew**  
cert

**revoke**  
cert

**view**  
attribute:\<name\>, cert, dynamic_groups, groups, jotp, jotp_rejoin,
key, logins_limited, lotp, roles, status, tokens, vote_script

## pass

**add**  
client, device, entry, host, node

**delete**  
entry

**edit**  
entry, keys

**remove**  
client, device, host, node

**view**  
clients, devices, entries, hosts, nodes

## policy

**disable**  
object

**enable**  
object

**view**  
policy_type, status

**Default ACLs**  
Written **+\<acl\>** for every object below it, whatever its type:
add:policy, del:policy.

## pool

**add**  
node

**disable**  
object

**enable**  
object

**remove**  
node

**view**  
dynamic_groups, nodes, status

## realm

**Alone**  
update_ca_data

**add**  
attribute:\<name\>, realm

**delete**  
attribute:\<name\>

**disable**  
auth, object, sync

**edit**  
attribute:\<name\>, secret

**enable**  
auth, object, sync

**view**  
attribute:\<name\>, auth, ca, ca_data, master, secret, status, sync

## resolver

**Alone**  
get_objects, run, test

**delete**  
objects

**disable**  
deletions, object, sync_units

**edit**  
key_attribute, sync_interval

**enable**  
deletions, object, sync_units

**view**  
deletions, key_attribute, resolver_type, status, sync_interval

## role

**add**  
attribute:\<name\>, device, dynamic_group, host, role, sync_user, token

**delete**  
attribute:\<name\>

**disable**  
object

**edit**  
attribute:\<name\>

**enable**  
object

**find**  
accessgroups, clients, groups, roles, scopes, shares

**remove**  
device, dynamic_group, host, role, sync_user, token

**view**  
accessgroups, attribute:\<name\>, devices, dynamic_groups, groups,
hosts, roles, scopes, shares, status, sync_users, tokens

## scope

**add**  
client, group, role, token

**disable**  
object

**edit**  
name, scope_id

**enable**  
object

**remove**  
client, group, role, token

**view**  
clients, groups, roles, scope_id, status, tokens

## script

**Alone**  
assign, dump, verify

**add**  
signature

**delete**  
signature

**disable**  
object

**edit**  
script

**enable**  
object

**verify**  
signature

**view**  
script, signatures, status

## share

**Alone**  
limit_hosts, unlimit_hosts

**add**  
group, host, master_password_token, no_mount_token, node, pool, role,
root_mount_token, share_key, token

**delete**  
share_key

**disable**  
add_script, mount_script, object, read_only, sotp_signing

**edit**  
add_script, force_create_mode, force_directory_mode, force_group,
home_share_permissions, mount_script, mount_timeout, root_dir,
sign_public_keys

**enable**  
add_script, mount_script, object, read_only, sotp_signing

**remove**  
group, host, master_password_token, no_mount_token, node, pool, role,
root_mount_token, token

**view**  
add_script, block_size, encrypted, force_create_mode,
force_directory_mode, force_group, groups, home_share,
home_share_permissions, hosts, limit_hosts, master_password_hash_params,
master_password_tokens, mount_script, mount_script_enabled,
mount_timeout, no_mount_tokens, nodes, pools, read_only, roles,
root_dir, root_mount_tokens, share_key, sotp_signing, status, tokens

## site

**add**  
attribute:\<name\>, fido2_ca_cert, sso_host, sso_logo, trust, unit

**delete**  
attribute:\<name\>, fido2_ca_cert, sso_logo, trust, unit

**disable**  
audit_log, auth, maintenance, object, oidc, sync, syslog

**dump**  
sso_logo

**edit**  
address, attribute:\<name\>, auth_fqdn, cluster_key, mgmt_fqdn,
oidc_pairwise_secret, radius_ca_cert, radius_cert, radius_key,
site_cert, sso_cert, sso_csrf_secret, sso_fqdn, sso_key, sso_secret,
tiqr_secret

**enable**  
audit_log, auth, maintenance, object, oidc, sync, syslog

**remove**  
sso_host

**renew**  
cert, oidc_key

**revoke**  
cert, oidc_key

**view**  
address, admin_role, admin_token, attribute:\<name\>, auth, auth_fqdn,
ca, cert, cert_key, cluster_key, fido2_ca_cert, maintenance, mgmt_cert,
mgmt_fqdn, mgmt_key, oidc, oidc_keys, oidc_pairwise_secret,
radius_ca_cert, radius_cert, radius_key, site_cert, sso_cert,
sso_csrf_secret, sso_fqdn, sso_hosts, sso_key, sso_secret, status, sync,
tiqr_secret, trusts, user_role

**Default ACLs**  
Written **+\<type\>:\<acl\>** (for example **+unit:edit**) for the type
unit. Written **+\<acl\>** for every object below it, whatever its type:
add, all, delete, disable, edit, enable, export, import, remove, rename,
view, view_all.

**Recursive default ACLs**  
Written **++\<type\>:\<acl\>** (for example **++accessgroup:edit**) for
the types accessgroup, ca, client, device, dictionary, group, host,
node, policy, pool, resolver, role, scope, script, share, token, unit,
user, vlan. Written **++\<acl\>** for every object below it, whatever
its type: add, all, delete, disable, edit, enable, export, import,
remove, rename, view, view_all, view_public.

## token

**Alone**  
force_password, set_temp_password, upgrade_pass_hash

**add**  
dynamic_group

**disable**  
object

**edit**  
auto_disable, device_name, password, pin, token_data

**enable**  
object

**find**  
accessgroups, groups, hosts, nodes, roles, scopes, shares

**remove**  
dynamic_group

**view**  
accessgroups, auth_script, auto_disable, device_name, dynamic_groups,
groups, hosts, nodes, pin, pin_status, roles, scopes, shares, status,
token_data, token_type, used_otp_salt

## unit

**add**  
accessgroup, attribute:\<name\>, ca, client, device, dictionary, group,
host, node, pass, policy, policy:authonaction, policy:autodisable,
policy:defaultgroups, policy:defaultpolicies, policy:defaultroles,
policy:defaultunits, policy:forcetoken, policy:idrange,
policy:logintimes, policy:objecttemplates, policy:password,
policy:tokenacls, pool, resolver, resolver:ldap, role, scope, script,
share, unit, user, vlan

**delete**  
accessgroup, attribute:\<name\>, ca, client, device, dictionary, group,
host, node, pass, policy, policy:authonaction, policy:autodisable,
policy:defaultgroups, policy:defaultpolicies, policy:defaultroles,
policy:defaultunits, policy:forcetoken, policy:idrange,
policy:logintimes, policy:objecttemplates, policy:password,
policy:tokenacls, pool, resolver, resolver:ldap, role, scope, script,
share, unit, user, vlan

**disable**  
object

**edit**  
attribute:\<name\>

**enable**  
object

**view**  
attribute:\<name\>, status

**Default ACLs**  
Written **+\<type\>:\<acl\>** (for example **+accessgroup:edit**) for
the types accessgroup, ca, client, device, dictionary, group, host,
node, pass, policy, pool, resolver, role, scope, script, share, token,
unit, user, vlan. Written **+\<acl\>** for every object below it,
whatever its type: add, all, delete, disable, edit, enable, export,
import, remove, rename, view, view_all, view_public.

**Recursive default ACLs**  
Written **++\<type\>:\<acl\>** (for example **++accessgroup:edit**) for
the types accessgroup, ca, client, device, dictionary, group, host,
node, pass, policy, pool, resolver, role, scope, script, share, token,
unit, user, vlan. Written **++\<acl\>** for every object below it,
whatever its type: add, all, delete, disable, edit, enable, export,
import, remove, rename, view, view_all, view_public.

## user

**Alone**  
decrypt, del_keys, encrypt, gen_keys, import_encrypt_key,
import_sign_key, set_temp_password, sign, unblock, verify

**add**  
attribute:\<name\>, photo, token

**delete**  
attribute:\<name\>, photo, session, token

**deploy**  
token

**disable**  
admin_access, auth_script, auto_mount, autosign, disabled_login,
key_caching, login_script, object, token

**dump**  
encrypt_private_key, encrypt_public_key, photo, sign_private_key,
sign_public_key

**edit**  
agent_script, attribute:\<name\>, auth_script, auto_disable,
encrypt_private_key, encrypt_public_key, group, key_cache_time,
key_mode, key_script, language, login_script, private_key_pass,
sign_private_key, sign_public_key

**enable**  
admin_access, auth_script, auto_mount, autosign, disabled_login,
key_caching, login_script, object, token

**find**  
groups, roles, signatures

**rename**  
token

**view**  
attribute:\<name\>, auto_disable, auto_mount, failcount, group,
key_cache_time, key_caching, session, status, tokens

**view_all**  
agent_script, auth_script, key_script, login_script, used_pass_salt

**Default ACLs**  
Written **+\<type\>:\<acl\>** (for example **+token:edit**) for the type
token.

## vlan

**Alone**  
assign

**add**  
device, host, role, token

**disable**  
object

**edit**  
vlan_id

**enable**  
object

**remove**  
device, host, role, token

**view**  
devices, hosts, roles, status, tokens, vlan_id

# THE ACLS PER POLICY TYPE

A policy of that type has the ACLs of **policy** above and these:

## authonaction

**add**  
hook, whitelist

**edit**  
reauth_expiry, reauth_timeout

**remove**  
hook, whitelist

**view**  
hooks, reauth_expiry, reauth_timeout, whitelist

## autodisable

**edit**  
auto_disable, unused_disable

**view**  
auto_disable, unused_disable

## defaultgroups

**add**  
default_group

**edit**  
default_group

**remove**  
default_group

**view**  
default_group, default_groups

## defaultpolicies

**add**  
default_policy

**remove**  
default_policy

**view**  
default_policies

## defaultroles

**add**  
default_role

**remove**  
default_role

**view**  
default_roles

## defaultunits

**add**  
default_unit

**edit**  
default_unit

**remove**  
default_unit

**view**  
default_units

## forcetoken

**edit**  
force_pass_types, force_token_types

**view**  
force_pass_types, force_token_types

## idrange

**add**  
idrange

**delete**  
idrange

**disable**  
id_check, id_range_recheck

**enable**  
id_check, id_range_recheck

**view**  
id_check, idrange

## logintimes

**edit**  
login_times

**view**  
login_times

## objecttemplates

**Alone**  
set_template

**view**  
templates

## password

**disable**  
lowercase, number, special, strength_checker, uppercase

**edit**  
password_min_len, pin_min_len, strength_checker, strength_checker_opts

**enable**  
lowercase, number, special, strength_checker, uppercase

**view**  
password_min_len, pin_min_len, strength_checker, strength_checker_opts

## tokenacls

**add**  
creator_acl, token_acl, user_acl

**del**  
creator_acl, token_acl, user_acl

**view**  
creator_acl, token_acl, user_acl

# THE ACLS PER RESOLVER TYPE

A resolver of that type has the ACLs of **resolver** above and these:

## ldap

**add**  
attribute_mapping, ldap_filter, ldap_server

**del**  
attribute_mapping, ldap_filter, ldap_server

**edit**  
ca_data, ldap_base, login_dn, login_password

**view**  
ca_data, ldap_base, ldap_server, login_dn, login_password

# THE ACLS PER TOKEN TYPE

A token of that type has the ACLs of **token** above and these:

## fido2

**disable**  
auth_script, offline, session_keep

**edit**  
attestation_cert, auth_script, offline_expiry, offline_unused_expiry, uv

**enable**  
auth_script, offline, session_keep

**view**  
attestation_cert, credential_data, offline_expiry, offline_status,
offline_unused_expiry, session_keep

## hotp

**Alone**  
generate, resync

**disable**  
auth_script, offline, pin, session_keep

**edit**  
auth_script, counter_check_range, mode, offline_expiry,
offline_unused_expiry, secret

**enable**  
auth_script, offline, pin, session_keep

**generate**  
otp, qrcode

**view**  
counter_check_range, counter_sync_time, mode, offline_expiry,
offline_status, offline_unused_expiry, secret, server_secret,
session_keep, token_counter

## link

**disable**  
auth_script, offline, session_keep

**edit**  
auth_script

**enable**  
auth_script, offline, session_keep

**view**  
destination_token, offline_expiry, offline_status,
offline_unused_expiry, session_keep

## motp

**Alone**  
generate

**disable**  
auth_script, offline, session_keep

**edit**  
auth_script, offline_expiry, offline_unused_expiry, secret,
timedrift_tolerance, validity_time

**enable**  
auth_script, offline, session_keep

**generate**  
otp

**view**  
offline_expiry, offline_status, offline_unused_expiry, secret,
session_keep, timedrift_tolerance, validity_time

## otp_push

**disable**  
auth_script

**edit**  
auth_script, phone_number, push_script, push_token

**enable**  
auth_script

**remove**  
nt_hash

**view**  
phone_number, push_script, push_token

## passkey

**disable**  
auth_script, offline, session_keep

**edit**  
auth_script, offline_expiry, offline_unused_expiry

**enable**  
auth_script, offline, session_keep

**view**  
credential_data, offline_expiry, offline_status, offline_unused_expiry,
session_keep

## password

**Alone**  
generate

**disable**  
2ftoken, auth_script, mschap, offline, session_keep

**edit**  
2ftoken, auth_script, offline_expiry, offline_unused_expiry,
password_hash

**enable**  
2ftoken, auth_script, mschap, offline, session_keep

**generate**  
mschap

**remove**  
nt_hash

**view**  
2ftoken, 2ftoken_status, mschap, nt_hash, offline_expiry,
offline_status, offline_unused_expiry, password_hash, session_keep

## script_otp

**edit**  
auth_script

## script_static

**edit**  
auth_script

## ssh

**add**  
signature

**delete**  
signature

**disable**  
2ftoken, auth_script, offline, session_keep

**edit**  
2ftoken, auth_script, card_type, key_type, offline_expiry,
offline_unused_expiry, ssh_private_key, ssh_public_key

**enable**  
2ftoken, auth_script, offline, session_keep

**verify**  
signature

**view**  
2ftoken, 2ftoken_status, card_type, key_type, offline_expiry,
offline_status, offline_unused_expiry, session_keep, signatures,
ssh_private_key, ssh_public_key

## tiqr

**disable**  
auth_script, offline, session_keep

**edit**  
auth_script, offline_expiry, offline_unused_expiry

**enable**  
auth_script, offline, session_keep

**view**  
identity_id, notification_address, notification_type, ocra_suite,
offline_expiry, offline_status, offline_unused_expiry, secret,
session_keep

## totp

**Alone**  
generate

**disable**  
auth_script, offline, pin, session_keep

**edit**  
auth_script, mode, offline_expiry, offline_unused_expiry, secret

**enable**  
auth_script, offline, pin, session_keep

**generate**  
otp, qrcode

**view**  
mode, offline_expiry, offline_status, offline_unused_expiry, secret,
server_secret, session_keep

## u2f

**disable**  
auth_script, offline, session_keep

**edit**  
attestation_cert, auth_script, offline_expiry, offline_unused_expiry

**enable**  
auth_script, offline, session_keep

**view**  
attestation_cert, key_handle, offline_expiry, offline_status,
offline_unused_expiry, session_keep

## yubikey_hmac

**disable**  
auth_script, offline, session_keep

**edit**  
auth_script, offline_expiry, offline_unused_expiry, secret,
timedrift_tolerance, validity_time

**enable**  
auth_script, offline, session_keep

**generate**  
otp

**remove**  
nt_hash

**view**  
hmac_challenge, hmac_id, offline_expiry, offline_status,
offline_unused_expiry, secret, session_keep, slot, smartcard_id,
timedrift_tolerance, validity_time

## yubikey_piv

**add**  
signature

**delete**  
signature

**disable**  
auth_script, offline, session_keep

**edit**  
auth_script, encrypt_public_key, key_type, offline_expiry,
offline_unused_expiry, sign_public_key, ssh_public_key

**enable**  
auth_script, offline, session_keep

**verify**  
signature

**view**  
dot1x_secret, encrypt_key_type, encrypt_public_key, key_type,
offline_expiry, offline_status, offline_unused_expiry,
private_key_backup, session_keep, sign_key_type, sign_public_key,
signatures, ssh_public_key

# SEE ALSO

**otpme**(1), **otpme**(7), **otpme-accessgroup**(1), **otpme-ca**(1),
**otpme-client**(1), **otpme-device**(1), **otpme-dictionary**(1),
**otpme-group**(1), **otpme-host**(1), **otpme-node**(1),
**otpme-pass**(1), **otpme-policy**(1), **otpme-pool**(1),
**otpme-realm**(1), **otpme-resolver**(1), **otpme-role**(1),
**otpme-scope**(1), **otpme-script**(1), **otpme-share**(1),
**otpme-site**(1), **otpme-token**(1), **otpme-unit**(1),
**otpme-user**(1), **otpme-vlan**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2026 the2nd. License: GPLv3
