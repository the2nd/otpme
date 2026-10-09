# NAME

otpme-tool - OTPme utility commands

# SYNOPSIS

**otpme-tool** *command* \[*options*\]

# DESCRIPTION

**otpme-tool** provides various utility commands for the OTPme system
including realm join/leave, login/logout, synchronization, cryptographic
operations, backup/restore and more.

# COMMANDS

## Realm

**join \[*options*\] \[*domain*\]**  
Join OTPme realm.

**leave \[*options*\] \[*domain*\]**  
Leave OTPme realm.

**get_realm**  
Show realm of this host.

**get_site**  
Show site of this host.

**get_user_site**  
Get site of login user.

## Session

**login \[**--node** *node*\] \[*username*\]**  
Login to OTPme realm.

**logout**  
Logout from OTPme realm.

**whoami**  
Show currently logged in user.

**who**  
Show all users currently logged in on this host (across TTYs and desktop
sessions).

**message \[**--user** *username*\] \[**--host** *hostname*\] \[**--all**\] \[**--title** *title*\] *text***  
Show a message box to users that are logged in.

The message is shown in a window with an OK button, in the desktop
session of the user. Give one of **--user**, **--host** or **--all**:
one user, all users logged in on one host, or all users of this site.
The command says how many users were told.

The window is drawn by the first helper the user's host has:
**kdialog**, **zenity**, **pinentry** or **xmessage**. A host with none
of them, or a user who is logged in on a terminal, gets a desktop
notification instead. Such a notification cannot be confirmed, so it
stays until the user closes it.

Nothing comes back when the user clicks OK.

Nodes may send messages. A host may send them when the site lists it in
**allow_user_messages**, see **otpme**(7). Only users of your own site
can be reached, because the message goes through the idled of that site.

**show_sessions**  
Get otpme-agent login sessions.

**get_login_session_id**  
Get otpme-agent login session ID.

**get_login_token**  
Show token of currently logged in user.

**get_login_token_type**  
Show token type of currently logged in user.

**get_login_pass_type**  
Show token password type used at login.

**get_tty**  
Get TTY for logged in user.

**get_display**  
Get **DISPLAY** of currently logged in user.

**get_sotp \[**--site** *site*\]**  
Get a SOTP for logged in user.

**get_srp**  
Get a SRP for logged in user.

**get_jwt *challenge***  
Request JWT from mgmtd.

**reneg**  
Try to renegotiate login session.

**reset_reauth**  
Reset auth_on_action reauth.

**do_reauth**  
Trigger a manual **auth_on_action** reauth, e.g. from a helper script
that wants to force the next protected action to prompt for
reauthentication.

## Synchronization

**sync \[**--realm** *realm*\] \[**--site** *site*\] \[*sync_type*\]**  
Tell OTPme daemon to start sync with master node. Sync types: sites,
objects, token_data, ssh_authorized_keys, nsscache.

**resync \[**--realm** *realm*\] \[**--site** *site*\] *sync_type***  
Tell OTPme daemon to start resync the given data type.

**sync_status**  
Get time of last successful sync.

**do_sync \[*options*\] *sync_type***  
Do a manual hostd sync. Sync types: objects, token_counters, used_otps,
nsscache, ssh_authorized_keys.

**--remove-orphan-objects** also removes local objects of a type this
host no longer syncs. A normal sync never names those objects, so
nothing else takes them away. It runs only after a sync that finished
and left no object behind.

**force_sync *object_id***  
Write an object again, whole. The search index, the ACLs and the LDIF
data are built from the object itself instead of being updated step by
step. Entries that were left over are removed this way. Use it when the
index of an object does not match the object.

This also sets the last modified time of the object, so other nodes
fetch it again. Hosts do not, because the data a host gets does not
include that time.

It takes an object ID, so it works for every object. This includes the
ones without a **touch** command, like a host inventory or a used OTP.
You need to be admin.

## Cryptographic Operations

**sign \[**--stdin-pass**\] *file* *sign_file***  
Create signature for given file using users RSA key.

**verify *sign_file* *file***  
Verify signature for given file using users RSA key.

**encrypt \[*options*\] *file* *outfile***  
Encrypt file using users RSA key (AES encryption).

**decrypt \[**--pass** *password*\] \[**--stdin-pass**\] *file* *outfile***  
Decrypt file using users RSA key.

## OTP and MSCHAP Generation

**gen_motp *epoch_time* *secret* *pin* \[*otp_count*\]**  
Generate mOTP OTPs from epoch time, secret and pin.

**gen_mschap *username* *password***  
Generate MSCHAP challenge/response from given username and password.

**gen_refresh *username* *password***  
Generate SRP (Session-Refresh-Password) from given password.

**gen_refresh_mschap *username* *password***  
Generate SRP challenge/response (MSCHAP) from given username and
password.

**gen_logout *username* *password***  
Generate SLP (Session-Logout-Password) from given password.

**gen_logout_mschap *username* *password***  
Generate MSCHAP SLP challenge/response from given username and password.

## Signer Management

**add_signer \[**--private**\] \[**--no-pin**\] \[**--no-verify-token-opts**\] \[**--allow-throwaway-key**\] \[**--tag** *tag*\] **--signer-type** *type* *object_id***  
Add signer. A token signature includes the token options (e.g.
*command=*) the SSH key may be used with, and those are verified against
the options the key is served with. **--no-verify-token-opts** turns
that check off for this signer.

**--allow-throwaway-key** is only for a **remote_access** signer. It
lets that signer ask for a shell on a key the job brings along, instead
of on a key this host already holds for the user. That way in needs
nothing but the signature of the job, so it is off unless you say
otherwise. See **otpme-shell**(1).

**del_signer \[**--private**\] *signer_uuid***  
Delete signer.

**enable_signer \[**--private**\] \[**--type** *signer_type*\] *signer_uuid***  
Enable signer.

**disable_signer \[**--private**\] \[**--type** *signer_type*\] *signer_uuid***  
Disable signer.

**update_signer \[**--private**\] \[**--no-pin**\] \[**--remove-gone**\] \[**--verify-token-opts**\|**--no-verify-token-opts**\] \[**--allow-throwaway-key**\|**--no-throwaway-key**\] \[**--signer-type** *type*\] \[*signer_uuid*\]**  
Update signer. Pins the current key of the user or role again, for
example after a key change.

The last two pairs change what the signer may ask for. Name neither of a
pair and it is left as it is: an update is usually about the pinned key,
and saying nothing must not take a permission away. This is the only way
to change one of them without removing the signer and adding it again.

**show_signer \[**--private**\] \[**--signer-type** *type*\] \[*signer_uuid*\]**  
Show signer(s). The table says whether the signature has to cover the
token options, and whether the signer may bring its own key for a remote
access session.

## Host Keys

**update_host_keys \[**--list**\] \[*host*\]**  
Take over the public keys of hosts whose key changed. Only with
**PIN_HOST_KEYS**, see **otpme.conf**(5).

With that parameter the public key of every host synced here is written
down, and a host is held to it. A key that differs from the one written
down does not replace it, and a remote access session to that host does
not open until somebody takes the new key over. This is where that
happens, and nothing else does it.

It shows every host whose key in the realm is not the one written down
here, with both fingerprints, and asks once. The keys are read from the
host objects when it runs, so what it shows is the realm as it is at
that moment. What it shows is what it will take over. Name a *host* to
take over that one alone.

You must be root, because the keys are read from this host's copy of the
realm, and the global **-f** skips the question. **--list** only shows
and changes nothing.

## Offline Token

**show_offline_token \[*token_id*\]**  
Show cached offline token(s).

**pin_offline_token**  
Pin cached offline token(s).

**unpin_offline_token**  
Unpin cached offline token(s).

## Object Management

**dump *cache_type* \[*object_id*\]**  
Tell OTPme daemon to dump the given cache.

**dump_object *object_id***  
Dump object.

**dump_index \[*object_id*\]**  
Dump object index.

**delete_object *object_id***  
Delete object.

**check_duplicate_ids *object_type***  
Check for duplicate uidNumber/gidNumber.

**search *attribute=value* *object_type=type* \[*return_type=uuid\|full_oid\|read_oid\|name*\]**  
Search OTPme objects.

## Import

**import \[**--password** *password*\] *file***  
Import object config.

**add_user *file***  
Create users listed in file.

**mass_object_add \[**--verify-only**\] \[**--procs** *N*\] *csv_file***  
Add objects from CSV file.

## Service Management

**reload**  
Tell OTPme to reload its config.

**index *command***  
Execute index command (start, status, stop, cli, init, drop, rebuild,
create_db_indices, drop_db_indices).

**cache *command***  
Execute cache command.

**radius *command***  
Execute radius command (start, status, stop, reload, restart, test).

## Private Keys in otpme-agent

These three are what the key script uses. They are listed here because a
human may want to look, not because a human has to use them.

otpme-agent holds the private keys of the login session in two shapes:
as the login brought them, wrapped with the key password of the user,
and unwrapped, as the key script left them after it was first asked to
use one. The unwrapped one lives for **key_cache_time** of the user.
Both are only handed to the login session they belong to. See
**enable_key_caching** in **otpme-user**(1).

**get_private_key **--role** *sign*\|*encrypt* \[**--decrypted**\]**  
Write a private key of the logged in user to stdout. Without
**--decrypted** the wrapped one, with it the unwrapped one. It fails
when the agent holds none, which is the normal answer before the key
script has been asked to use the key, and after the cache time ran out.

**add_private_key **--role** *sign*\|*encrypt* \[**--decrypted**\]**  
Give the agent a private key, read from stdin. **--decrypted** for the
unwrapped one, which is then kept for the cache time.  
From stdin, because a private key on a command line is a private key in
the process list.

**del_private_key **--role** *sign*\|*encrypt***  
Take a private key away from the agent, both shapes of it. The next use
asks for the key password again. This is how to drop a cached key
without logging out.

## Key and Certificate

**regen_master_key**  
Regen AES master key.

**renew_auth_key**  
Renew host auth key.

**renew_cert**  
Renew host certificate.

## SSH Agent

**start_ssh_agent**  
Start users SSH agent script.

**stop_ssh_agent**  
Stop users SSH agent script.

**restart_ssh_agent**  
Restart users SSH agent script.

**ssh_agent_status**  
Get users SSH agent script status.

## Backup and Restore

**backup **-d** *backup_dir* \[**--remove-older-than** *time*\] \[**--dry-run**\]**  
Write backup to backup directory.

**restore {**-d** *restore_dir* \| **-f** *restore_file*}**  
Restore from backup.

## Benchmark

**login_benchmark \[**--procs** *N*\] \[**--node** *node*\] *csv_file***  
Run login benchmark.

## Smartcard

**detect_smartcard \[**-t** *type1,type2*\]**  
Detect connected smartcards.

# OPTIONS

## Join Options

**--jotp *JOTP***  
Join using the given JOTP.

**--host-type *node\|host***  
Join host as type.

**--unit *UNIT***  
Join host to the given unit.

**--host-key-len *LENGTH***  
Host/Node key length.

**--site-key-len *LENGTH***  
Site key length.

**--trust-site-cert**  
Trust any site certificate.

**--check-site-cert *FINGERPRINT***  
Check the site certificate fingerprint.

**--no-daemon-start**  
Don't start OTPme daemons after joining realm.

## Leave Options

**--lotp *LOTP***  
Leave using the given LOTP.

**--offline**  
Leave realm without talking to OTPme servers.

**--keep-host**  
Do not delete node/host object on server side.

**--no-keep-host**  
Delete node/host object on server side.

**--keep-data**  
Keep all data (realm data, certs, offline tokens).

**--keep-cache**  
Keep cached data (offline tokens, nsscache etc.).

**--keep-cert**  
Do not revoke host certificate when leaving.

**--keep-auth-key**  
Do not revoke host auth key when leaving.

## Encrypt Options

**--rsa**  
Encrypt file using RSA encryption.

**--no-rsa**  
Disable use of RSA public keys for encryption of AES keys.

**-u *USERNAME***  
Encrypt file with public key of given user.

**--pass *PASSWORD***  
Use password to encrypt/decrypt the file (AES only).

**--stdin-pass**  
Read password/passphrase from stdin.

**--force-pass**  
Force encryption with password (AES only).

## Do_sync Options

**--realm *REALM***  
Realm to sync.

**--site *SITE***  
Site to sync.

**--resync**  
Do a complete resync.

**--offline**  
Sync offline token data.

**--sync-older-objects**  
Sync objects even if they are older than the local ones.

**--ignore-changed-objects**  
Sync objects even if they changed while syncing.

## Signer Options

**--private**  
Operate on a signer of the logged in user instead of a system-wide
signer. Without this option, signer commands operate on the host's
signer configuration (root only).

**--no-pin**  
Do not pin signature keys. By default signer keys are pinned, which
means only the exact key present at the time the signer was added is
trusted. With **--no-pin**, any valid key of the signer object is
accepted.

**--signer-type *TYPE***  
What this signer is trusted for. Supported types: **token**,
**key_script**, **push_script**, **auth_script**, **login_script**,
**agent_script**.  
Types for configuration jobs (see **otpme-deploy**(1)): **sw_mgmt**,
**repo_mgmt**, **signer_mgmt**, **service_mgmt**, **file_mgmt**,
**host_mgmt**. A host only runs a job if it is signed by a signer of the
job type. **file_mgmt**, **signer_mgmt** and **host_mgmt** give full
control over the host.

**--tag *TAG***  
Add tag to signer (can be used multiple times).

Global options are available for all commands. See **otpme**(1) for
details.

# EXAMPLES

**otpme-tool join --jotp abc123 example.com**  
Join OTPme realm

**otpme-tool login alice**  
Login as user alice

**otpme-tool sync objects**  
Start object sync

**otpme-tool backup -d /backup/otpme**  
Create backup

**otpme-tool detect_smartcard**  
Detect connected smartcards

# FILES

*/var/lib/otpme/*  
OTPme data directory

# SEE ALSO

**otpme**(1), **otpme**(7)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
