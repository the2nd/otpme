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

**join \[**--jotp** *jotp*\] \[**--host-type** **host**\|**node**\] \[**--unit** *unit*\] \[**--host-key-len** *bits*\] \[**--ca-key-len** *bits*\] \[**--ca-valid** *days*\] \[**--site-key-len** *bits*\] \[**--site-valid** *days*\] \[**--trust-site-cert**\|**--check-site-cert** *fingerprint*\] \[**--joind-uri** *uri*\] \[**--no-daemon-start**\] \[*domain*\]**  
Make this machine a host or a node of a realm. You must be root, and the
machine must not be in a realm yet.

**Finding the realm.** The joind of the realm is looked up in DNS, as
the SRV record **\_otpme-join.\_tcp.***domain*. Realm and site come from
the TXT records **\_otpme-realm.\_tcp.***domain* and
**\_otpme-site.\_tcp.***domain*, or from the global options **-r** and
**-s**. Without *domain* it is *site*.*realm* when **-r** and **-s** are
given, else the domain of the FQDN of this machine.  
**--joind-uri** names the joind instead of the SRV record, e.g.
**tcp://node1.berlin.example.org:2024**; 2024 is the port of joind.

**Who may join.** With **--jotp** nobody logs in: the JOTP is the
one-time password that **otpme-host add** or **otpme-node add** printed,
and the object has to exist.  
Without it you log in as a user: the one of the global option **-u**,
else root. The user needs the ACL **join:host** or **join:node** on the
access group **JOIN**. An object that is not there yet is made in
**--unit**, which needs **add:host** or **add:node** on that unit.

**--host-type** is **host** by default. A host joins the site of the
joind it asks.

**--unit** is **hosts** or **nodes** by default. An object that exists
has to be in this unit: one in another unit needs **--unit**.

**Keys.** **--host-key-len**, or **--node-key-len**, is the length of
the key of the certificate of this machine, when it has none yet. The
default is the config variable **default_host_key_len** or
**default_node_key_len**.  
The first node of a site makes the CA of the site and the site
certificate as well, the way **otpme-realm init** does it for the first
site: **--ca-key-len** and **--ca-valid** are for the CA, which the CA
of the parent site or the realm signs, **--site-key-len** and
**--site-valid** for the site certificate. The defaults are
**default_ca_key_len**, **default_ca_validity**,
**default_site_key_len** and **default_site_validity**. Any other join
leaves these four alone.

**The site certificate.** join shows the fingerprint of the certificate
of the site it connects to and asks whether to trust it.
**--check-site-cert** compares it instead, given as **sha256:***hex*,
**sha1:***hex* or the sha256 hex alone; the colons and capitals of
**openssl x509 -fingerprint** are fine. **--trust-site-cert** trusts any
certificate.

At the end join starts the OTPme daemons, unless **--no-daemon-start**.
It prints the LOTP that **leave** takes, where the host or node has
LOTPs enabled.  
An object that has joined already is refused; the global option **-f**
joins it again.

**leave \[**--lotp** *lotp*\] \[**--offline**\] \[**--keep-host**\|**--no-keep-host**\] \[**--keep-data**\] \[**--keep-cache**\] \[**--keep-cert**\]**  
Take this machine out of its realm. You must be root. The master node
cannot leave.

leave stops the OTPme daemons and **otpme-agent**, tells the realm, and
removes the data of the realm from this machine: its objects,
**/var/lib/otpme**, **/var/cache/otpme**, **/var/spool/otpme**, the
certificate and its key, and the auth key.

With **--lotp** nobody logs in: the LOTP is the one join printed.
Without it you log in as a user: the one of the global option **-u**,
else the one logged in to **otpme-agent**, else root. The user needs
**leave:host** or **leave:node** on the access group **JOIN**. Either
way the realm checks the certificate of this machine.

On the realm a host is kept by default: its certificate is revoked and
it is disabled, and it can join again. A node is deleted.
**--keep-host** and **--no-keep-host** say otherwise.

**--keep-cert**  
Keep the certificate: it is not revoked, it stays on this machine, and
the object is kept on the realm.

**--keep-cache**  
Keep **/var/cache/otpme**, with the users and groups of nsscache.

**--keep-data**  
Remove nothing but the files that make this machine a member,
**/etc/otpme/otpme.uuid** and **/etc/otpme/otpme.host_type**. It takes
**--keep-cert** with it.

**--offline**  
Do not tell the realm, which changes nothing there: the object stays,
the certificate is not revoked. For a machine that cannot reach its
realm any more.

**get_realm**  
Print the realm this machine is a member of. Nothing is printed when it
is in none.

**get_site**  
Print the site this machine is a member of, the same way.

**get_user_site**  
Print the site of a user: the one of the global option **-u**, else the
one logged in to **otpme-agent**. It asks hostd, so the machine has to
be in a realm.

## Session

A login to the realm is kept by **otpme-agent**, one per system user.
These commands ask the agent of the user who runs them, for the session
of the login they run in.

**login \[**--node** *node*\] \[**--no-authorize-host**\] \[*username*\]**  
Log in to the realm. It starts **otpme-agent** if it is not running,
asks for the password or OTP of the user, and leaves the session with
the agent. The user is *username*, else the one of the global option
**-u**, else the system user. A user who is logged in already is
refused.  
This is not the login of PAM: no shares are mounted, and nothing is kept
for offline logins.

**--node *node***  
Send the login to this node, instead of the one DNS names.

**--no-authorize-host**  
Do not ask whether the token may log in on this host, through the roles
and groups of the host, and do not apply **logins_limited**. For tests,
e.g. to log in as a user on a node without assigning the token there.
The policies of the token, the user and the access group still apply. A
login through PAM always asks.

**logout**  
Log out of the realm. The shares mounted for the session are unmounted
first; if that fails, nothing is logged out. Then the session is ended
on every site it is logged in to, and the agent drops it. A site that
could not be told is named in the error; the agent drops the session all
the same.

**whoami**  
Print the name of the user that is logged in.

**who**  
Print the users that are logged in to the realm, on every host of the
site: user, login token, host, IP address, when the agent connected,
when the user logged in, the session and the version of OTPme. A user
logged in more than once on a host is one line.  
It asks the idled of the master node, so it says nothing while the
cluster is not healthy.  
Nodes may run it. A host may when the site has **allow_who_from_hosts**
on, or lists it in **allow_who**, see **otpme**(7). That is decided for
the host: every user who may read its certificate key may run it there.

**host_who**  
Print the hosts and nodes that wait to be told of a job: host, type, IP
address and when they connected. A host that is listed hears of a new
job at once, for example of **otpme-shell**; one that is not picks it up
at its next sync.  
Who may run it is the same as for **who**.

**message \[**--user** *username*\] \[**--host** *hostname*\] \[**--all**\] \[**--title** *title*\] *text***  
Show a message box to users that are logged in.

The message is shown in a window with an OK button, in the desktop
session of the user. Give one of **--user**, **--host** or **--all**:
one user, all users logged in on one host, or all users of this site.
The command says how many users it found logged in, the way **who**
lists them; each session of a user gets the message.

The window is drawn by the first helper the user's host has:
**kdialog**, **zenity**, **pinentry** or **xmessage**. A host with none
of them gets a desktop notification instead. Such a notification cannot
be confirmed, so it stays until the user closes it. A session without a
display of its own gets the window on the display of the user's other
processes, else on **:0**.

Nothing comes back when the user clicks OK.

Nodes may send messages. A host may send them when the site lists it in
**allow_user_messages**, see **otpme**(7). Only users of your own site
can be reached, because the message goes through the idled of that site.

**show_sessions \[*pid*\]**  
List the sessions of the agent you may see: the PID of the login, the
token, the pass type, realm and site, whether it is a login or the
passphrase of an SSH key, who else may use it, and the sites it is
logged in to. With the *pid* of a login: its sessions on each site, with
login time, last and next renegotiation, timeouts, whether it may go
offline, and the session UUID.

**get_login_session_id**  
Print the ID of the agent session of this login, the one PAM puts into
**OTPME_LOGIN_SESSION**.

**get_login_token**  
Print the token the user logged in with.

**get_login_token_type**  
Print the type of that token.

**get_login_pass_type**  
Print what was given at login, for example **otp** or **static**.  
These three also answer for an offline login.

**get_tty**  
Print the TTY the login was made on.

**get_display**  
Print the **DISPLAY** PAM gave the login.

**get_sotp \[**--site** *site*\]**  
Print an SOTP, a one-time password made from the session: it is how the
tools of a logged-in user, e.g. the mount of a share, authenticate as
that session. It is valid for about a minute.  
With **--site** it is made for the session at that site of the realm.
Without one there yet, the agent logs in there first, which the site of
the user has to trust.

**get_srp**  
Print the SRP, the session refresh password. Sent instead of a password,
it keeps the session on the node from running into its unused timeout,
and authenticates nothing. It changes with every renegotiation.

**get_jwt *challenge***  
Print a JWT that authd signs with the key of the site, for *challenge*,
after you authenticated once more with password or OTP. It is what an
**auth_on_action** policy asks for; as a command it is there to test
that.

**reneg**  
Renegotiate the session with the site of the global options **-r** and
**-s**, by default the one of this host, now and not when it is due. A
session that cannot be renegotiated any more, because it timed out or
the node refuses it, is ended. With **-v** it says when it worked.

**reset_reauth**  
Forget that you authenticated again for an **auth_on_action** policy, so
that the next action it protects asks.

**do_reauth**  
Authenticate again for an **auth_on_action** policy now, with password
or OTP. Actions it protects do not ask again until its
**reauth_timeout** has passed.  
Both are kept by the mgmtd of the node you are connected to, not for the
realm.

## Synchronization

**sync \[**--realm** *realm*\] \[**--site** *site*\] \[**--request-site-cert**\] \[*sync_type*\]**  
Tell hostd to start a sync now and not when it is due. The sync runs in
the background: the command prints “Command queued” and does not wait
for it. Use **sync_status** to see how it went. Only root and the user
**otpme** may do this. The sync types:

**sites**  
The realm and site objects.

**objects**  
The objects this host gets. A node gets the objects of its own site from
the other nodes of the site, not this way. A sites sync runs first.

**token_data**  
The used OTPs and token counters of the offline logins on this host.

**ssh_authorized_keys**  
The SSH keys this host gets, and the **authorized_keys** files made from
them.

**nsscache**  
The NSS cache, built from the objects this host already has.

Without a sync type it syncs objects, token_data and
ssh_authorized_keys.

**--realm *realm*** and **--site *site*** sync the objects of this realm
or site only. They work with the sync type objects only.

**--request-site-cert** takes the site certs anew from the sites. Each
host keeps the cert of every site in */etc/otpme/ssl/*, and a sync does
not replace it. After a **renew_cert** of a site, run **sync
--request-site-cert sites** on the hosts and nodes of the realm. The
cert is taken only if it is the cert of that site and the CA of the site
issued it and did not revoke it. It works with the sync type sites only.

**resync \[**--realm** *realm*\] \[**--site** *site*\] **objects**\|**nsscache****  
Like **sync**, but full: **objects** compares every object with the
site, not only the ones that changed since the last sync, and then
builds the NSS cache new. **nsscache** builds the NSS cache new from
scratch. Nothing is removed before. **--realm** and **--site** work as
with **sync**.

**sync_status \[*sync_type*\]**  
Show for each site and sync type when the last sync run started, and how
it went: how long ago that was, how far a running one is, or when it
last failed. “Never synced” means no run started yet. Every user may run
it. On a node the objects of its own site are not listed, see **sync**.

**do_sync \[**--realm** *realm*\] \[**--site** *site*\] \[**--resync**\] \[**--offline**\] \[**--sync-older-objects**\] \[**--ignore-changed-objects**\] \[**--remove-orphan-objects**\] *sync_type***  
Do a sync here and now, without hostd: it connects to syncd itself and
waits until the sync is done. It works when hostd does not run. If it
cannot connect, it uses what an earlier sync left in the sync cache on
disk. Only root may do this. The sync types: **objects**,
**token_counters**, **used_otps**, **nsscache** and
**ssh_authorized_keys**, which also writes the **authorized_keys**
files.

**--realm *realm*, --site *site***  
The site to sync with. The default is the site of this host.

**--resync**  
Compare every object, not only the ones that changed since the last
sync.

**--offline**  
Sync the token data of the offline logins. A host can sync
token_counters and used_otps only with this.

**--sync-older-objects**  
Also take objects that are older than the local ones. For a node, with
its own site.

**--ignore-changed-objects**  
Also take objects that changed on the site while the sync ran.

**--remove-orphan-objects**  
Also remove local objects of a type this host no longer syncs. A normal
sync never names those objects, so nothing else takes them away. It runs
only after a sync that finished and left no object behind.

**force_sync *object_id***  
Write an object again, whole. The search index, the ACLs and the LDIF
data are built from the object itself instead of being updated step by
step. Entries that were left over are removed this way. Use it when the
index of an object does not match the object.

This also sets the last modified time of the object, so other nodes
fetch it again. Hosts do not, because the data a host gets does not
include that time.

It takes an object ID, so it works for every object. This includes the
ones without a **touch** command, like a host inventory or a used OTP. A
session cannot be written this way. It fails while the site is in
maintenance. You need to be admin.

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

A signer of type **password** says whose signature of
**password_store_members** this host trusts. Without one, **otpme-pass**
encrypts nothing on this host. See **otpme-pass**(1).

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

It also removes the keys of hosts that are gone. Nothing else does: the
sync never takes a key away.

## User Keys

**update_user_keys \[**--list**\] \[*user*\]**  
Take over the encrypt public keys of users whose key changed. Only with
**PIN_USER_KEYS**, see **otpme.conf**(5).

**otpme-pass** encrypts the keys of passwords with these keys, see
**otpme-pass**(1). With that parameter the encrypt public key of every
user synced here is written down. A member whose key differs from the
one written down gets no key until somebody takes the new key over here.

It works like **update_host_keys**: it shows every user whose key in the
realm is not the one written down, with both fingerprints, and asks
once. Name a *user* to take over that one alone. It also removes the
keys of users that are gone.

You must be root, and only on a host. The global **-f** skips the
question, and **--list** only shows and changes nothing.

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
