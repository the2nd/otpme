# NAME

pam_otpme - PAM module that logs users in to an OTPme realm, also
offline

# SYNOPSIS

    auth [success=1 default=ignore] pam_python.so pam_otpme.py [options...]
    session required pam_python.so pam_otpme.py

# DESCRIPTION

**pam_otpme** logs a user of the realm in on this host. It is a Python
script that **pam_python.so** runs, see INSTALLATION.

**auth**  
Checks the login at the nodes, with a password, an OTP, a smartcard or
an SSH key, see OPTIONS, and starts the OTPme agent, which holds the
login session. On a screen unlock it only checks the user again. Then
PAM sets the credentials, and pam_otpme adds the user to the dynamic
groups, see **ALLOW_DYNAMIC_GROUPS** in **otpme.conf**(5).

**session**  
Starts the SSH agent when the session starts, see **start_ssh_agent**.
When the session ends, it stops the SSH agent and the OTPme agent.

**account**  
Lets every user through: who may log in is checked by **auth**.

## Offline logins

When the nodes do not answer, a user can log in with an offline copy of
the login token. The host writes one at a login with
**cache_login_tokens**, if the token allows it:

> **otpme-token enable_offline *token***

The copy is encrypted with a key made from the password, see
**offline_key_func**.

With session keeping, the copy also holds the login session, and an
offline login takes it up again instead of starting a new one:

> **otpme-token enable_session_keep *token***

## Shares

At a login, the shares of the user are mounted, also when an offline
login takes up a kept session. It is on by default; to turn it off for a
user:

> **otpme-user disable_auto_mount *user***

# INSTALLATION

**pam_otpme** is a Python script that **pam_python.so** runs, with the
Python of the system. That Python has to be the version OTPme is
installed for, e.g. 3.11.

1\. pam_python  
On Debian and Ubuntu:

**apt-get install libpam-python**

2\. The script  
It comes with OTPme as *etc/otpme/deploy/pam/pam-python/pam_otpme.py*
below the *site-packages* directory, and is in
*/etc/otpme/deploy/pam/pam-python/* once *etc/otpme* is copied to */etc*
(see *README.md*). **pam_python.so** looks for a script without a path
in */lib/security/*, so link it there:

**ln -s /etc/otpme/deploy/pam/pam-python/pam_otpme.py /lib/security/**

3\. The path to OTPme  
The script reads */etc/otpme/PYTHONPATH*, one directory per line, to
find OTPme in its virtual environment, e.g.:

**/opt/otpme/lib/python3.11/site-packages/**

4\. The PAM config  
*/etc/otpme/deploy/pam/* has *otpme-auth*, *otpme-account* and
*otpme-session*. Copy them to */etc/pam.d/* and, in the PAM config of a
service, replace **@include common-auth** and the others with **@include
otpme-auth** and so on. *deploy/pam/examples/sshd* in the sources of
OTPme shows it for SSH.

# OPTIONS

The options go after **pam_otpme.py** on the PAM line, separated by
spaces. An option it does not know is ignored, a value it does not know
gives a warning in the log and the default stays.

**cache_login_tokens**  
After an online login, keep the login token on this host for offline
logins, if it may be kept: see **enable_offline** in **otpme-token**(1).

**try_first_pass**  
Take the password a PAM module above this one asked for; without one,
ask.

**use_first_pass**  
Take the password a PAM module above this one asked for; without one,
the login fails.

Without either of them, pam_otpme asks for the password itself.

**nullok**  
Allow an empty password, e.g. for a **fido2** token that needs none.

**send_password=*auto\|false***  
Whether the password goes to the nodes. **auto** (default): if the token
of the user needs it there. **false**: never, e.g. for a token that is
checked with an SSH key, so the password does not leave the host.

**use_smartcard=*auto\|true\|false***  
Use a smartcard, e.g. the HMAC-SHA1 slot of a YubiKey. **auto**
(default): if one is plugged in. **true**: always; without one the login
fails. **false**: never.

**use_ssh_agent=*auto\|true\|false***  
Log in with an SSH key from an SSH agent, e.g. a YubiKey with the GPG
applet for an **ssh** token of OTPme. **auto** (default): if the agent
has a key the nodes know. **true**: always, and start the agent; without
a key the login fails. **false**: never, and do not start the agent.

**start_ssh_agent=*auto\|true\|false***  
Start an SSH agent at login. **auto** (default): if the nodes send SSH
keys of the user. **true**: always. **false**: never. When it is not
set, **use_ssh_agent=true** and **false** set it to the same.

**unlock_via_offline_token**  
On a screen unlock, check the password against the offline copy of the
login token, if this host has one, and ask no node.

**do_dot1x=*auto\|force\|false***  
Log the network port in with 802.1X at login, through a NetworkManager
connection (default: **false**). pam_otpme writes the user name and the
password or OTP into that connection, see **dot1x_token_types**, and
brings it up. Nothing happens when the interface of the connection has
no link, e.g. on WLAN. **auto**: only when the default gateway does not
answer a ping. **force**: always; the connection goes down and up again.
On a screen unlock, when the gateway does not answer, the connection is
brought up again with what the login wrote into it, because the user may
not change the connection. That works with the OTP of **yubikey_piv**
only when the access group the RADIUS server checks the port login
against has sessions, see **enable_sessions** in
**otpme-accessgroup**(1): then the OTP of the login may be used again
while the session lasts.

The connection has to exist. **ca-cert** and **domain-suffix-match**
make the supplicant check the RADIUS server before it sends anything.
All nodes of a site have the certificate of the site, with
*\<site\>.\<realm\>* as its name, so one **domain-suffix-match** covers
every RADIUS node. Identity and password are only placeholders here:

    nmcli connection add type ethernet con-name "dot1x-lan" ifname enp0s25 \
        802-1x.eap ttls \
        802-1x.phase2-auth pap \
        802-1x.ca-cert /etc/otpme/ssl/ca.pem \
        802-1x.domain-suffix-match berlin.example.org \
        802-1x.anonymous-identity "anonymous@example.org" \
        802-1x.identity "user" \
        802-1x.password "pass"

**dot1x_connection=*name***  
The NetworkManager connection (default: **dot1x-lan**).

**dot1x_token_types=*type\[,type...\]***  
What the password of the connection is made from; without it,
**do_dot1x** does nothing and says so in the log. **yubikey_piv**: an
OTP derived by the YubiKey, which asks for its PIN; used when one is
plugged in. **password**: the password of the login.

**dot1x_timeout=*seconds***  
How long to wait for the connection to come up (default: **10**).

**offline_key_func=*func\[;opt:val,...\]***  
How the key that encrypts the offline copy of the login token is made
from the password, see **cache_login_tokens** (default: **Argon2_i**).
**Argon2_i**, **Argon2_d** and **Argon2_id** work; another function
gives a warning in the log and the default stays. After **;** come
options as ***opt*:*val***, separated by **,**; an option not given
keeps its default:

**iterations**  
(default: **3**)

**memory**  
In KiB (default: between **min_mem** and **max_mem**, by the free memory
of the host).

**min_mem**  
In KiB (default: **65536**).

**max_mem**  
In KiB (default: **262144**).

**threads**  
(default: **4**)

    offline_key_func=Argon2_id;max_mem:524288,threads:2

**check_offline_pass_strength\[=*policy\[;score:iterations,...\]\]***  
A weak password gets more **iterations** of **offline_key_func**, so its
offline copy takes longer to guess. A password policy gives the password
a score from 0 (weak) to 10 (strong), and the score picks the
iterations. **iterations** given to **offline_key_func** is then not
used.

*policy*  
The password policy, see **otpme-policy**(1) (default: **auto**, the
password policy of the host). Without a policy the score is 0, and the
log says so.

*score:iterations*  
How many iterations a score gets. The pairs you give replace these of
the default:

    0:6,1:6,2:6,3:5,4:5,5:5,6:3,7:3,8:3,9:3,10:3

So a score of 0 to 2 gets 6 iterations, 3 to 5 gets 5, and 6 to 10 gets
3.

    check_offline_pass_strength=password_strength;0:8,1:8,2:8

**online_greeting**  
After a login to the realm, show "You are logged in to REALM
'\<realm\>'.".

**offline_greeting**  
After a login with the offline copy of the token, show "You are logged
in offline!".

**show_errors**  
When the login fails, show why, e.g. "Login failed: Host disabled".
Without it, the reason is only in the log.

**message_timeout=*seconds***  
How long to wait after each message pam_otpme shows, so it can be read
(default: **2**).

**connect_timeout=*seconds***  
How long to wait for the connection to the nodes at login (default:
**3**).

**connection_timeout=*seconds***  
How long to wait for an answer of the nodes at login (default: **30**).

**create_home**  
Create the home directory of the user if it does not exist, with
mode 0700. That happens before the password is checked, because the
OTPme agent that the login starts keeps its files there.

**home_skel=*path***  
Copy the new home directory from this directory, e.g. */etc/skel*.
Without **create_home** it does nothing.

**debug**  
Write debug messages to the log.

# EXAMPLES

## Login with offline copies

*/etc/otpme/deploy/pam/otpme-auth* has these lines. When pam_otpme lets
the user in, **success=1** skips **pam_deny**; else **pam_deny** ends
the login:

    auth [success=1 default=ignore] pam_python.so pam_otpme.py \
        try_first_pass cache_login_tokens \
        use_smartcard=auto use_ssh_agent=auto start_ssh_agent=auto \
        create_home home_skel=/etc/skel \
        check_offline_pass_strength=password_strength;0:6,1:6,2:6,3:5,4:5,5:5,6:3,7:3,8:3,9:3,10:3
    auth requisite pam_deny.so
    auth required pam_permit.so

## A stronger key for the offline copies

Argon2_id with up to 512 MiB, and the iterations from the strength of
the password, scored by the password policy of the host:

    auth [success=1 default=ignore] pam_python.so pam_otpme.py \
        try_first_pass cache_login_tokens \
        offline_key_func=Argon2_id;max_mem:524288 \
        check_offline_pass_strength

## No new offline copies

Without **cache_login_tokens** no new offline copy is written, so a
login without the nodes works only with a copy from before.
**show_errors** shows why a login fails:

    auth [success=1 default=ignore] pam_python.so pam_otpme.py try_first_pass show_errors

## The session

*/etc/otpme/deploy/pam/otpme-session* has pam_otpme in the session part.
When the session starts, it starts the SSH agent, see
**start_ssh_agent**. When the session ends, it stops the SSH agent and
the OTPme agent, which logs the user out when needed:

    session required pam_python.so pam_otpme.py

# FILES

*/lib/security/pam_otpme.py*  
The link to the script, see INSTALLATION.

*/etc/otpme/PYTHONPATH*  
Directories the script puts in front of the Python path, one per line,
e.g. the *site-packages* of the virtual environment of OTPme. Without
it, the script finds OTPme only when it runs from the sources.

*/etc/otpme/deploy/pam/*  
*otpme-auth*, *otpme-account* and *otpme-session*, to copy to
*/etc/pam.d/*. They are there once *etc/otpme* from *site-packages* is
copied to */etc*, see INSTALLATION.

*/etc/otpme/otpme.conf*  
Where pam_otpme logs to, see PAM LOGGING in **otpme.conf**(5).

*/var/log/otpme/pam.log*  
The log with **PAM_USE_LOGFILE**, see **PAM_LOGFILE** in
**otpme.conf**(5).

*/var/cache/otpme/offline/\<user uuid\>/*  
The offline copies of the tokens of a user, see **cache_login_tokens**,
and the login session kept with them, see **enable_session_keep** in
**otpme-token**(1).

*/var/cache/otpme/env/\<user\>/*  
What a login of the user leaves for later, e.g. for the SSH agent when
the session ends.

The two directories in */var/cache/otpme/* move with **CACHE_DIR** in
**otpme.conf**(5).

# SEE ALSO

**otpme-token**(1), **otpme-user**(1), **otpme-accessgroup**(1),
**otpme-policy**(1), **otpme-tool**(1), **otpme.conf**(5),
**pam.conf**(5), **pam**(7)

pam_python is described in the Debian package **libpam-python-doc**.

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
