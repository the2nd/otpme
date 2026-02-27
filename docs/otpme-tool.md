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

**show_sessions**  
Get otpme-agent login sessions.

**get_login_session_id**  
Get otpme-agent login session ID.

**get_login_token**  
Show token of currently logged in user.

**get_login_pass_type**  
Show token password type used at login.

**get_tty**  
Get TTY for logged in user.

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

**add_signer \[**--private**\] \[**--no-pin**\] \[**--tag** *tag*\] **--signer-type** *type* *object_id***  
Add signer.

**del_signer \[**--private**\] *signer_uuid***  
Delete signer.

**enable_signer \[**--private**\] \[**--type** *signer_type*\] *signer_uuid***  
Enable signer.

**disable_signer \[**--private**\] \[**--type** *signer_type*\] *signer_uuid***  
Disable signer.

**update_signer \[**--private**\] \[**--no-pin**\] \[*signer_uuid*\]**  
Update signer.

**show_signer \[**--private**\] \[*signer_uuid*\]**  
Show signer(s).

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

**--no-memory-cache**  
Do not cache objects in memory.

**--sync-older-objects**  
Sync objects even if they are older than the local ones.

**--ignore-changed-objects**  
Sync objects even if they changed while syncing.

## Signer Options

**--private**  
Operate on signer of the logged in user.

**--no-pin**  
Do not pin signature keys.

**--signer-type *TYPE***  
Signer type.

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
