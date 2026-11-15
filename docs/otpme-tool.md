# NAME

otpme-tool - work on this machine and your session: join, login, sync,
signers, backup

# SYNOPSIS

**otpme-tool** *command* \[*options*\]

# DESCRIPTION

**otpme-tool** works on the machine it runs on and on the session of the
user who runs it. The other otpme-\* commands manage objects of the
realm; otpme-tool manages none.

With it a machine joins and leaves a realm, a user logs in and out, a
sync is started by hand, the signers and the pinned keys of the machine
are kept, and a node is backed up and restored. The rest are aids for
tests and repairs: OTP and MSCHAP generation, raw objects, import and a
login benchmark.

Most commands talk to **hostd** on this machine or to **otpme-agent** of
the user. **login**, **logout**, **leave** and the object commands go to
the daemons of the realm. Each command says who may run it; many need
root.

# COMMANDS

## Realm

**join \[**--jotp** *jotp*\] \[**--hostname** *hostname*\] \[**--host-type** **host**\|**node**\] \[**--unit** *unit*\] \[**--host-key-len** *bits*\] \[**--ca-key-len** *bits*\] \[**--ca-valid** *days*\] \[**--site-key-len** *bits*\] \[**--site-valid** *days*\] \[**--trust-site-cert**\|**--check-site-cert** *fingerprint*\] \[**--joind-uri** *uri*\] \[**--no-daemon-start**\] \[*domain*\]**  
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

**The name.** The host or node gets the hostname of this machine as its
name. **--hostname** gives it another name, e.g. **web1**. It is a name,
not an FQDN. The domain to find the joind in stays that of this machine.
After the join OTPme uses the name of the object, not the hostname of
the machine.

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

**sign \[**--stdin-pass**\] *file* *sig_file***  
Sign *file* with the sign key of your user (RSA or Ed25519) and write
the signature to *sig_file*, **-** for stdout. The signature file says
who signed it. The key is used where it is: on the server, through
otpme-agent, or on a YubiKey (PIV).

**--stdin-pass** reads the passphrase of the key from stdin.

**verify *sig_file* *file***  
Check the signature of *file*. The signer is read from *sig_file*, and
their public sign key is fetched from the realm, so you can check the
signatures of any user. Prints what openssl says, for example **Verified
OK**, and fails when the signature does not match.

**encrypt \[**-u** *user*\] \[**--rsa**\] \[**--no-rsa**\] \[**--force-pass**\] \[**--pass** *password*\] \[**--stdin-pass**\] *file* *outfile***  
Encrypt *file* and write it to *outfile*, **-** for stdout. By default
the file is encrypted with a random AES key, and that key with your
encrypt key (RSA or X25519), so only you can decrypt it. The output
decrypts itself: run it, and it calls **otpme-tool decrypt**.

**-u *user***  
Encrypt for that user, with their encrypt key.

**--rsa**  
Encrypt the file itself with the key, no AES. With RSA the file can only
be as large as the key allows, about 190 bytes for 2048 bits.

**--no-rsa, **--force-pass****  
Protect the AES key with a passphrase instead of a key. Anyone with the
passphrase can decrypt the file, and it then decrypts itself with bash
and openssl alone. **--force-pass** does this also where the key script
is set to GPG.

**--pass *password*, **--stdin-pass****  
The passphrase. Without them you are asked. **--pass** shows in the
process list, so prefer **--stdin-pass**.

**decrypt \[**--pass** *password*\] \[**--stdin-pass**\] *file* *outfile***  
Decrypt a file made by **encrypt** and write it to *outfile*, **-** for
stdout. What it needs is read from the file: your key, or the
passphrase. The passphrase, or the one of your private key, is given
with **--pass** or **--stdin-pass**, or asked for.

The four commands are done by the key script of your user, see
**otpme-user**(1).

## OTP and MSCHAP Generation

These print what a client would send, to test logins with
**otpme-auth**: **otpme-auth verify** takes an OTP, an SRP or an SLP as
the password, and **otpme-auth verify_mschap** takes a challenge and a
response. They are worked out here, without asking a node. The password
is given on the command line and shows in the process list.

**gen_motp *epoch_time* *secret* *pin* \[*otp_count*\]**  
Print the mOTP for the time *epoch_time*, in seconds since the epoch,
with *secret* and *pin*. mOTP counts in steps of 10 seconds, so the last
digit of *epoch_time* does not matter. With *otp_count* it prints that
many, one per step from *epoch_time* on.

**gen_refresh *username* *password***  
Print the SRP of a session that logged in with *password*. It holds
until the session is renegotiated, which gives it a new password. The
SRP of your own login is printed by **get_srp**.

**gen_logout *username* *password***  
Print the SLP of a session that logged in with the OTP *password*. A
login with a static password has an SLP made from its session, not from
the password.

**gen_mschap *username* *password***  
**gen_refresh_mschap *username* *password***  
**gen_logout_mschap *username* *password***  
The same for MSCHAP: print the challenge and the response a client would
send for *password*, for the SRP of a session that logged in with it, or
for its SLP, and the NT key that comes out of it. The lines are
**NT_KEY**, **MSCHAP_CHALLENGE** and **MSCHAP_RESPONSE**.

## Signer Management

A signer says whose signatures this host trusts, and for what: a user or
a role, and a signer type. Signers are files in */etc/otpme/signers/*,
owned by root, and they are read again for each check, so a change
counts at once. Only for a token signer the **authorized_keys** files
change later, with the next sync of the SSH keys (**sync
ssh_authorized_keys**).

The signer types:

> -   **token**, **key_script**, **push_script**, **auth_script**,
>     **login_script**, **agent_script**, **backup_script**,
>     **share_script**: what a token or a script must be signed by.
>
> -   **password**: whose signature of **password_store_members** this
>     host trusts, see below.
>
> -   **remote_access**, **sw_mgmt**, **repo_mgmt**, **signer_mgmt**,
>     **service_mgmt**, **file_mgmt**, **host_mgmt**: configuration
>     jobs, see **otpme-deploy**(1). A host only runs a job that a
>     signer of the job type signed. **file_mgmt**, **signer_mgmt** and
>     **host_mgmt** give full control over the host.

**--private** works on the signers of your own user, in
*\~/.otpme/signers/*, instead of the ones of the host. A user that is
not root always works on their own. Only **token**, **key_script** and
**agent_script** signers can be private. The host asks them only where
**FORCE_TOKEN_SIGNERS**, **FORCE_KEY_SCRIPT_SIGNERS** or
**FORCE_AGENT_SCRIPT_SIGNERS** in *otpme.conf* allow it, and by default
it does not.

**add_signer \[**--private**\] \[**--no-pin**\] \[**--no-verify-token-opts**\] \[**--allow-throwaway-key**\] \[**--tag** *tag*\]... **--signer-type** *type* *object_id***  
Trust the signatures of *object_id* for *type*. *object_id* is a user or
a role, given as OID, for example **'user\|example.org/alice'** or
**'role\|example.org/berlin/admins'**.

By default the keys are pinned: the sign key the user has now, or the
ones the members of the role have now. A key that comes later, of a new
member or after a key change, is not trusted until **update_signer**. A
role whose members have no sign key at all is refused.

**--no-pin** pins nothing: each check takes the keys the user or the
members of the role have then. A new member is trusted at once, and so
is a new key.

With **--tag *tag*** a signature counts only if it carries this tag too.
Give it more than once for more, and a signature has to carry all of
them. An OID, *type*:*name*, e.g. **group:admins**, or
*type*:*site*/*name*, e.g. **role:munich/admins**, stands for that
object. *type*:*name* means the object of this site; if there is none,
the one of that name in the realm. A name that is in more than one other
site needs the site, e.g. **role:munich/REALM_USER**: every site has a
role of that name. A tag for an object that does not exist is refused.
Anything else is taken as it is, for example **sometag** or
**sometag=value**.

**--no-verify-token-opts** is for a **token** signer. A token signature
includes the token options (e.g. *command=*) the SSH key may be used
with, and those are checked against the options the key is served with.
This option turns that check off for this signer.

**--allow-throwaway-key** is only for a **remote_access** signer. It
lets that signer ask for a shell on a key the job brings along, instead
of on a key this host already holds for the user. That way in needs
nothing but the signature of the job, so it is off unless you say
otherwise. See **otpme-shell**(1).

A signer of type **password** says whose signature of
**password_store_members** this host trusts. Without one, **otpme-pass**
encrypts nothing on this host. See **otpme-pass**(1).

**del_signer \[**--private**\] *signer_uuid***  
Remove the signer.

**enable_signer \[**--private**\] \[**--signer-type** *type*\] \[*signer_uuid*\]**  
**disable_signer \[**--private**\] \[**--signer-type** *type*\] \[*signer_uuid*\]**  
Switch one signer on or off, or with **--signer-type** alone every
signer of that type. A signer that is off is not asked.

**update_signer \[**--private**\] \[**--remove-gone**\] \[**--verify-token-opts**\|**--no-verify-token-opts**\] \[**--allow-throwaway-key**\|**--no-throwaway-key**\] \[**--signer-type** *type*\] \[*signer_uuid*\]**  
Pin the keys the user or the members of the role have now, for example
after a key change or a new member. One signer, or with
**--signer-type** alone every signer of that type. A signer that cannot
be updated is named at the end, and the others are updated all the same.

Keys that are gone stay pinned, so what they signed still checks out.
**--remove-gone** drops them: a signer whose user or role was deleted is
not updated, and a role loses the keys of the members it does not have
anymore.

The last two pairs change what the signer may ask for. Name neither of a
pair and it is left as it is: an update is usually about the pinned
keys, and saying nothing must not take a permission away. This is the
only way to change one of them without removing the signer and adding it
again.

**show_signer \[**--private**\] \[**--signer-type** *type*\] \[*signer_uuid*\]**  
List the signers: the UUID (with **\*** when its keys are pinned),
whether it is on, its type, whether the token options are checked,
whether it may bring its own key for a remote access session, the user
or role, the pinned keys and the tags. A signer or key is marked
**deleted** when its user or role was deleted, **removed** when the
member left the role, **outdated** when the key changed, and **no key**
when the user has no sign key.

## Host Keys

**update_host_keys \[**--list**\] \[*host*\]**  
Take over the public keys of hosts whose key changed. Only on a host,
and only with **PIN_HOST_KEYS**, see **otpme.conf**(5). A node holds the
tree itself, so there is nothing to hold it to.

With that parameter the public key of every host synced here is written
down, in */var/spool/otpme/host_keys/*, and a host is held to it. A key
that differs from the one written down does not replace it, and a remote
access session to that host does not open until somebody takes the new
key over. This is where that happens, and nothing else does it.

It shows every host whose key in the realm is not the one written down
here, with both fingerprints, and asks once. The keys are read from the
host objects when it runs, so what it shows is the realm as it is at
that moment. What it shows is what it will take over. Name a *host* to
take over that one alone. A name that is not a host or node of the realm
is refused.

You must be root, because the keys are read from this host's copy of the
realm, and the global **-f** skips the question. **--list** only shows
and changes nothing.

Without a *host* it also removes the keys of hosts that are gone.
Nothing else does: the sync never takes a key away.

## User Keys

**update_user_keys \[**--list**\] \[*user*\]**  
Take over the encrypt public keys of users whose key changed. Only with
**PIN_USER_KEYS**, see **otpme.conf**(5).

**otpme-pass** encrypts the keys of passwords with these keys, see
**otpme-pass**(1). With that parameter the encrypt public key of every
user synced here is written down, in */var/spool/otpme/user_keys/*. A
member whose key differs from the one written down gets no key until
somebody takes the new key over here.

It works like **update_host_keys**: it shows every user whose key in the
realm is not the one written down, with both fingerprints, and asks
once. Name a *user* to take over that one alone. A name that is not a
user of the realm is refused. Without a *user* it also removes the keys
of users that are gone.

You must be root, and only on a host. The global **-f** skips the
question, and **--list** only shows and changes nothing.

## Offline Token

After a login a host keeps a copy of the login token, and of its second
factor token, so the user can log in again when no node can be reached,
see **pam_otpme**(8). These commands work on that cache of the user who
runs them.

**show_offline_token \[**--show-secret**\] \[*token_id*\]**  
List the cached tokens: **login_token** and the UUIDs of the others,
with their path, and whether the cache is pinned.

With *token_id*, **login_token** or a UUID, show what the token keeps
for an offline login: the secret of an HOTP token, the password hash of
a password token. The values are hidden unless **--show-secret** is
given, because a secret on the screen ends up in a scrollback or a
screenshot.

**pin_offline_token**  
Pin the cache. A login no longer replaces it with the tokens the node
sends, and every login, online too, checks the cached token first and
fails when that fails.

**unpin_offline_token**  
Unpin the cache: the next login replaces it again, and an online login
does not check it.

## Object Management

These work on the raw objects and caches, for repairs and debugging. All
but **dump** go to mgmtd and need an admin. An admin that is not the
superuser does not get the realm, the sites, the nodes, the admin user
and its token, and the objects of **site_admin_blacklist**, with
**dump_object**, **dump_index** and **delete_object**. *object_id* is an
OID, for example **'user\|example.org/alice'**.

**dump acl_cache\|**sync_map** \[*object_id*\]**  
Print a cache of hostd on this host. Only root. With **acl_cache**,
*object_id* limits it to one object, given as full OID, or to the OIDs a
pattern with **\*** matches.

**dump_object *object_id***  
Print the configuration of an object as it is stored.

**dump_index *object_id***  
Print the index entry of an object: its columns, its index attributes,
its LDIF and its ACLs.

**delete_object *object_id***  
Delete an object as it is stored, after asking (the global **-f** does
not ask). This is not the delete of the object's own command: it skips
ACLs, the trash, policies, and what belongs to the object, the tokens of
a user for example. Use it for what that command cannot remove, like an
index entry without a file.

**check_duplicate_ids user\|**group****  
Look for uidNumbers (**user**) or gidNumbers (**group**) used twice, in
all sites. Prints each number with the two names, or “No duplicate IDs
found.”

**search attribute=*attr* value=*value* \[**object_type=***type*\] \[**return_type=***type*\]**  
Search the index of this site. *value* may hold **\*** as wildcard.
Without **object_type** every type is searched.

**return_type** is **full_oid** by default. **uuid**, **name** and
**read_oid** work for everyone; an admin also gets **path**,
**rel_path**, **oid**, **object_type**, **checksum**, **sync_checksum**,
**last_used**, **template** and **ldif**. A user that is not an admin
needs **view_public** on the attribute searched for.

## Import

Both need an admin and go to mgmtd.

**import \[**--password** *password*\] *file***  
Import an object from *file*, as **otpme-***type*** export** wrote it,
with **--password** when it was exported with one. The object is written
as it is in the file, with its UUID; ACLs and policies are not asked. If
it exists, import asks before it writes over it. Only objects of this
realm and site, and the realm and its sites themselves.

**mass_object_add \[**--verify-only**\] \[**--procs** *n*\] *csv_file***  
Add users, groups and roles from a CSV file: one object per line, **;**
between the columns, no header line. A column that holds a list
separates its items with commas.

    user;name;unit;group;groups;default_role;roles;default_token_type;default_token_password;ldif_attributes
    group;name;unit;ldif_attributes
    role;name;unit;groups;roles

**ldif_attributes** is *attr***=***value***,***attr***=***value*.
Without **uidNumber** or **gidNumber** there, the IDRange policy of the
unit, else of the site, gives the number. An empty unit is the default
unit.

First every line is checked: that it has its columns, that the name is
free and not in the file twice, that the unit exists and has an IDRange
policy where one is needed. **--verify-only** stops there. Then the
objects are added, by *n* processes (default: half the CPUs), one type
after the other in the order of the file.

A line that fails is said at once, and the others are added all the
same; nothing is rolled back. At the end it says how many objects were
added and lists every line that was not, with why. If one was not, the
command ends with an error, so a script can see it.

## Service Management

The services under OTPme. Only root.

**index *command***  
Run the search index: the database next to the object files, PostgreSQL,
MySQL or SQLite (**INDEX** in **otpme.conf**(5)). The commands:

**start, **stop**, **restart**, **status****  
The database server. **stop** and **restart** need OTPme stopped.

**reload**  
Make the server read its configuration again.

**cli**  
Open a database shell on the index.

**init**  
Create a new, empty index. Needs OTPme stopped.

**drop**  
Delete the index, without asking. Needs OTPme stopped.

**rebuild \[*object_dir*\]**  
Throw the index away and build it again from the object files, keeping
the last used times. Needs OTPme stopped. With *object_dir* only that
object, while OTPme runs.

**fix**  
Remove the entries whose object file is gone.

**backup**  
Write every entry as JSON to stdout.

**restore *file***  
Put a backup back into an empty index. Needs OTPme stopped.

**create_db_indices, **drop_db_indices****  
Create or remove the indices of the database itself. Ones that are there
already are left alone.

**cache *command***  
Run the cache, redis or memcached (**CACHE** in **otpme.conf**(5)):
**start**, **stop**, **restart**, **status**, and **cli** \[*args*\] for
a shell on it. **stop** and **restart** need OTPme stopped. **stop**
loses what is cached, unless **REDIS_PERSISTENCE** is set.

**radius *command***  
Run freeradius on this node: **start**, **stop**, **restart**,
**status**. **reload** restarts it on every node of the site, through
hostd.

**test \[**--mschap**\] *username* password nas_id secret**  
Send a request to freeradius here and say whether it was accepted; with
**--mschap** as EAP-MSCHAPv2. The password shows in the process list.

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

All three are for root, on the host or node itself.

**regen_master_key**  
Write the master key file of this node again, from the master password
(asked for) and the salt kept here: the same key, for when the file was
lost. Only when **KEY_COMMAND** in **otpme.conf**(5) is a file. If a key
file is there, it asks before writing over it, and refuses a password
that gives another key.

**renew_auth_key**  
Make a new auth key pair for this host or node. The public key goes to
its object, the private one into its key file, and OTPme and otpme-agent
are reloaded.

**renew_cert**  
Get a new certificate for this host or node, for the key it has, from
the CA of its site. OTPme and otpme-agent are reloaded.

## SSH Agent

These commands run the agent script of the user. When you are logged in,
the script comes from the server. Else it comes from the offline tokens.
They need an OTPme login session: PAM sets OTPME_LOGIN_SESSION at login.
When you are online and agent script signers are set, the script
signature is checked first. The default script starts ssh-agent. With
**--gpg-agent** or **--gpg-smartcard** in the script options it starts
gpg-agent.

**start_ssh_agent**  
Start the SSH agent. Print the agent variables (SSH_AUTH_SOCK,
SSH_AGENT_PID) as shell commands. To set them in your shell, use **eval
"$(otpme-tool start_ssh_agent)"**. If the script prints no variables,
e.g. because the agent is already running, its output goes to stderr.

**stop_ssh_agent**  
Stop the SSH agent. The default script stops all agents of the user,
also those of other sessions.

**restart_ssh_agent**  
Stop and start the SSH agent. Print the agent variables like
**start_ssh_agent**.

**ssh_agent_status**  
Print "Running", or "Stopped" with exit code 1.

## Backup and Restore

**backup **-d** *backup_dir* \[**--remove-older-than** *time*\] \[**--dry-run**\]**  
Write all objects of this node into a new directory
*backup_dir*/YYYY-mm-dd_HH:MM:SS. There is one JSON file per object, in
one directory per object type. The object configs stay encrypted, as
they are on disk. So a restore needs the same master key (see
**regen_master_key**). Share data and the index are not part of the
backup. Directories are created with mode 0700. At the end, failed
objects are listed and the exit code is 1. Needs root.

**--remove-older-than*** time*  
Write no backup. Remove the backup directories in *backup_dir* that are
older than *time*. *time* is a number with m (minutes), h (hours), d
(days), w (weeks), M (months of 30 days) or Y (years of 365 days), e.g.
30d.

**--dry-run**  
With **--remove-older-than**: remove nothing, only print what would be
removed.

**restore {**-d** *restore_dir* \| **-f** *restore_file*}**  
Restore from a backup.

**-d*** restore_dir*  
Restore all objects of one backup directory, e.g.
*backup_dir*/2026-10-24_03:00:00. This also restores the objects of the
other sites. It is meant to set up a node from scratch. The OTPme daemon
must be stopped. It creates the index if it is missing, writes the
objects and builds the DB indices. Then it starts the cache and updates
the nsscache. Object types that are missing in the backup are skipped.
At the end, failed objects are listed and the exit code is 1. Needs
root.

**-f*** restore_file*  
Restore one object from its backup file, through the management daemon.
Only an object of this realm and site, and the realm and its sites
themselves; the objects of another site are restored on that site, or
all at once with **-d**. If the object exists, you are asked before it
is written over. Needs admin rights.

## Benchmark

**login_benchmark \[**--procs** *N*\] \[**--node** *node*\]... \[**--logout**\] *csv_file***  
Log in many users at the same time and measure the speed. *csv_file* has
one line per login: username,password. There is no header line. Each
login is a real login with the password, but without otpme-agent, login
session, offline tokens or shares. Each successful login makes a session
on the server, like a normal login. Without **--logout** the sessions
stay until their timeout.

For each login, a line is printed with the average seconds per login so
far. At the end, the number of logins, the failed logins and the
requests per second are printed. If logins or logouts failed, the exit
code is 1.

**--procs*** N*  
Run *N* logins at the same time. The default is half the number of CPUs.

**--node*** node*  
Send the logins to this node. Can be given more than once; the logins
then go to the nodes in turn. Without it, the node is found the normal
way.

**--logout**  
After the measurement, log out the sessions of the benchmark. The
logouts are not part of the measured time.

## Smartcard

**detect_smartcard \[**-t** *type*\[,*type*...\]\]**  
Search for connected smartcards and print what is found. This is the
same search that login does. For each type, "Searching for smartcard:
*type*" is printed, then the devices found. If no smartcard is found,
the exit code is 1.

The types are yubikey_hmac, yubikey_hotp, yubikey_gpg, yubikey_piv, u2f
and fido2. yubikey_hmac, yubikey_hotp and yubikey_gpg find any YubiKey;
they do not check that it is set up for this type. yubikey_piv finds a
YubiKey with a key in the PIV slot AUTHENTICATION. u2f and fido2 also
search through PC/SC (e.g. NFC readers) if pcscd runs.

**-t*** type\[,*type*...\]*  
Search only for these types.

# OPTIONS

The options of each command are described with that command above.

Global options are available for all commands. See **otpme**(1) for
details.

# EXAMPLES

The examples use the site **berlin** of the realm **example.org**.

## Taking this machine into the realm

**otpme-tool join --jotp 12345678**  
Run on the machine itself, with the JOTP that **otpme-host add** (or
**otpme-node add**) printed. See **otpme-host**(1).

## Logging in and out

**otpme-tool login alice**  
Log in as alice. otpme-agent keeps the session.

**otpme-tool whoami**  
Who is logged in here.

**otpme-tool logout**  
End the session.

**eval "$(otpme-tool start_ssh_agent)"**  
Start the SSH agent of the user and set its variables in this shell.

## Starting a sync by hand

**otpme-tool sync objects**  
Fetch the objects of the site now. Without this, the next regular sync
fetches them.

**otpme-tool sync --request-site-cert sites**  
Fetch the new site certificate after **otpme-site renew_cert**.

## A nightly backup

**otpme-tool backup -d /backup/otpme**  
Write a new backup directory. Put this in cron.

**otpme-tool backup -d /backup/otpme --remove-older-than 30d**  
A second cron line: remove backups older than 30 days.

**otpme-tool restore -f /backup/otpme/2026-10-24_03:00:00/user/example.org+alice.json**  
Bring back the user alice from that backup.

## A login benchmark

**otpme-tool login_benchmark --procs 32 --node node1 --node node2 --logout users.csv**  
Log in the users of users.csv on two nodes in turn, then log the
sessions out again.

## Which smartcard is plugged in

**otpme-tool detect_smartcard -t fido2,yubikey_piv**  
Search only for FIDO2 and PIV keys.

# FILES

*/etc/otpme/otpme.conf*  
The config file of the machine, see **otpme.conf**(5).

*/etc/otpme/otpme.uuid*, */etc/otpme/otpme.host_type*  
What makes the machine a member: **join** writes them. **leave
--keep-data** removes these two and nothing else.

*/etc/otpme/ssl/*  
The certificate and keys of the machine, and the certificate of each
site as **\<realm\>-\<site\>.pem**. The sync does not replace a site
certificate, **sync --request-site-cert sites** does.

*/etc/otpme/signers/\<type\>/*  
The signers of the machine, one directory per signer type, as
**add_signer** writes them. With **--private**, and for a user that is
not root: *\~/.otpme/signers/*.

*/var/lib/otpme/*  
On a node: the objects of the realm. **backup** reads them, **restore**
writes them, and **dump_object**, **delete_object** and the **index**
commands work on them.

*/var/cache/otpme/*  
What the sync writes for the machine: **nsscache/** with the users and
groups, **offline/** with the offline tokens, **ssh/authorized_keys/**
with the SSH keys of the users. **leave** removes it, unless
**--keep-cache**.

*/var/spool/otpme/host_keys/*, */var/spool/otpme/user_keys/*  
The public keys written down with **PIN_HOST_KEYS** and
**PIN_USER_KEYS**. **update_host_keys** and **update_user_keys** take
new ones over.

# SEE ALSO

**otpme**(1), **otpme**(7), **otpme.conf**(5), **pam_otpme**(8),
**otpme-realm**(1), **otpme-site**(1), **otpme-host**(1),
**otpme-node**(1), **otpme-user**(1), **otpme-script**(1),
**otpme-pass**(1), **otpme-deploy**(1), **otpme-shell**(1),
**otpme-backup**(1)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2026 the2nd. License: GPLv3
