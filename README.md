# OTPme

OTPme is a distributed, multi-site authentication and authorization system
that combines identity management, PKI, single sign-on, RADIUS, LDAP, PAM
and file shares under a single directory tree.

Its central design principle: every user carries **many independent tokens**
instead of one shared password. A user might unlock their workstation with a
FIDO2 hardware key, mount OTPme file shares with the same key, connect to
WLAN with a per-device password over RADIUS, and use a dedicated
application-scoped token for CalDAV/CardDAV/IMAP from a smartphone — all
managed under one identity. Lose a laptop, delete that laptop's token; no
other device is affected and no password anywhere needs rotating.

## What OTPme offers

- **Token types** — passwords (Argon2/PBKDF2/HKDF), HOTP/TOTP, FIDO2/U2F,
  WebAuthn passkeys, YubiKey HMAC challenge-response, YubiKey in PIV mode,
  mOTP, SSH keys, short-lived SSO temp-passwords, script-driven tokens for
  custom auth backends, and *link tokens* that delegate to another user's
  token.
- **Access control by client + access group** — every service (RADIUS NAS,
  LDAP consumer, SSO relying party, …) is an OTPme *client* bound to
  an *access group*; only tokens or roles in that group can authenticate.
  Access groups carry per-service session lifetime and parallel-session
  caps, and can be nested into child access groups. The SSO access group
  is an exception — its rights do not cascade to children, so each
  service listed in the SSO portal can be permissioned individually.
- **Object-level ACLs** — orthogonal to access groups: fine-grained
  view/modify/delete/enable/disable permissions on individual objects,
  inheritable down the unit tree, assignable to a user/token or a role.
- **Realms, sites, units** — a distributed topology with intra-site cluster
  replication (`clusterd`) and cross-site synchronisation (`syncd`/`hostd`),
  optional cross-site *trust cascades* for federated login.
- **Built-in PKI** — realm CA, per-site CAs, and node/host certs for
  daemon-to-daemon TLS; no external CA required.
- **Web SSO portal with OIDC provider** — front-end can be deployed into a
  DMZ (`ssohost` install) with no backend secrets on the box.
- **RADIUS** via FreeRADIUS (rlm_python module or `otpme-auth` as
  ntlm_auth drop-in) — WLAN, VPN, anything RADIUS-capable, including
  MSCHAP / MS-CHAPv2 (PEAP, EAP-MSCHAPv2) for Windows-flavoured
  supplicants.
- **LDAP frontend** (`ldapd`) — external services bind through a familiar
  LDAP interface; the `dc=<client>` component selects which access group
  the bind is scoped to.
- **PAM module** for system login, with `nsscache` integration for POSIX
  user/group lookups.
- **Offline authentication** — during an online login, hosts cache the
  token and session data encrypted with an Argon2i-derived key from the
  user's password / PIN / smartcard response. When the server is
  unreachable, hosts authenticate against the local cache with OTP replay
  protection; used OTPs and counters resync back to the server on
  reconnect. Expiry is bounded by both login-age and inactivity.
- **File shares** — FUSE-mounted OTPme shares served by `fsd`, with
  optional transparent per-share encryption (share key wrapped per user).
  Shares can be pinned to a *node pool* to control placement and locality.
- **Encrypted backups** to a dedicated backup host, with e-mail reporting.
- **Roles, groups, resolvers** — role-in-role composition, groups usable
  as sync groups, and resolvers that import users from external sources.
- **Policies** — a pluggable rule engine: `password` (quality / dictionary
  strength), `authonaction` (step-up reauth on sensitive actions),
  `logintimes` (cron-style login windows), `autodisable`
  (time-boxed accounts / tokens), `forcetoken` (restrict which token types
  and methods a service accepts), `idrange` (sequential or random UID/GID
  allocation), and `objecttemplates` / `default{groups,roles,units,policies}`
  for zero-touch defaults on freshly created objects.
- **Server-side scripts** (`scriptd`) — hooks executed during specific
  events: `auth` scripts run inside the authentication flow, `share`
  scripts fire when a share is created or mounted (e.g. to set up
  directories or permissions), and `backup` scripts run as pre/post
  hooks around backup jobs.
- **Client-side agent** (`otpme-agent`) — holds session state and, when
  configured, keeps an unlocked YubiKey PIV handler so subsequent
  sign / verify / encrypt / decrypt operations (e.g. mounting an
  encrypted share) don't prompt for the PIV PIN again.
- **Trash & restore** — soft-deletion with inspectable dumps before
  restore.
- **Audit log** — dedicated audit trail of who changed which object,
  independent of daemon logs.
- **Per-object config inheritance** — most parameters cascade
  site → unit → node/host → user → token, with most-specific match wins.

Full architecture, daemon layout and config-parameter reference are in the
[otpme.7](https://otpme.readthedocs.io/en/latest/otpme.7/) manpage.
A hands-on walkthrough is in the
[Getting Started guide](https://otpme.readthedocs.io/en/latest/getting-started/).

---

# Installation instructions

> **Warning:** OTPme is alpha software. Do not use it in production. Expect breaking changes, incomplete features and bugs.

Full documentation is available at [https://otpme.readthedocs.io](https://otpme.readthedocs.io).

Manpages can be installed with:

```bash
otpme-install-manpages
```

## Install debian dependencies
apt-get install python3.11-venv gobjc++ python3-pybind11 python3-dev build-essential cmake gcc dbus-x11 freeradius freeradius-python3 libacl1-dev libnss-cache liboath0 liboath-dev libpcsclite1 libpq-dev libre2-9 libre2-dev libsystemd-dev pkg-config postgresql postgresql-server-dev-all pwgen pyflakes3 redis redis-server redis-tools libpcsclite-dev ykcs11 fuse3 libpam-python

### Disable installed services
systemctl stop redis  
systemctl disable redis  
systemctl stop postgresql  
systemctl disable postgresql  
systemctl stop freeradius  
systemctl disable freeradius  

## Install otpme

### Add otpme system user
useradd -r -U -d /var/lib/otpme otpme

### Enable nsswitch nsscache module
Edit /etc/nsswitch.conf and append 'cache' to the lines passwd, shadow and group.

### Create python venv
python3 -m venv /opt/otpme  
. /opt/otpme/bin/activate

### Install otpme and dependencies
pip3 install cython

Pick the install variant matching what this machine should do:

| Command | Role |
|---|---|
| `pip3 install otpme` | **host** — client + otpme-agent + PAM + nsscache + offline login. Default. |
| `pip3 install 'otpme[backuphost]'` | **backup host** — backup server for nodes, shares and hosts. |
| `pip3 install 'otpme[ssohost]'` | **SSO portal host** — front-end for the SSO/OIDC web portal. Holds no backend secrets, so it can be deployed into the DMZ. |
| `pip3 install 'otpme[node]'` | **node** — full server install, all features. |
| `pip3 install 'otpme[node,dev]'` | full server + dev tools (`pytest`, `coverage`, `ruff`). |

The `backuphost` and `ssohost` roles are activated by setting
`BACKUP_SERVER` resp. `SSO_SERVER` to `True` in `/etc/otpme/otpme.conf`.

## Copy configuration files
cp -a /opt/otpme/lib/python3.11/site-packages/etc/otpme /etc/  
cp -a /etc/otpme/otpme.conf.dist /etc/otpme/otpme.conf

### Edit /etc/otpme/otpme.conf
POSTGRES_PG_CTL_BIN="/usr/lib/postgresql/15/bin/pg_ctl"

### Create PYTHONPATH file with path to venv (e.g. /opt/otpme/lib/python3.11/site-packages/)
/etc/otpme/PYTHONPATH

## Init your otpme realm
otpme-realm --api -ddee --color-logs -f init --ca-key-len 2048 --site-key-len 2048 --node-key-len 2048 --dicts english,en-top10000,common-passwords,us-female,us-male,us-surnames,abbreviations-it --id-ranges "uidNumber:s:100000-200000,gidNumber:s:100000-200000" yourrealm.tld yoursite localhost 127.0.0.1  

Note: Scan the generated QRCode with the "Google Autenticator App" and note the PIN of the admin token.

## Start OTPme daemons
otpme-controld start

## Login with admin token
You need to input pin+otp.  
otpme-tool login

## Add optional U2F/fido2 attestation certificates from https://developers.yubico.com/FIDO/yubico-fido-ca-certs.txt.
wget https://developers.yubico.com/FIDO/yubico-fido-ca-1.pem  
wget https://developers.yubico.com/FIDO/yubico-fido-ca-2.pem  
otpme-site add_fido2_ca_cert yoursite yubico-fido-ca-1.pem  
otpme-site add_fido2_ca_cert yoursite yubico-fido-ca-2.pem  
otpme-site config yoursite check_fido2_attestation_cert True  

## Disable gpg-agent (systemd) to use yubikey/GPG card with the PAM module.
systemctl --global mask --now gpg-agent.service gpg-agent.socket gpg-agent-ssh.socket gpg-agent-extra.socket gpg-agent-browser.socket  
