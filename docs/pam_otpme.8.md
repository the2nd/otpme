# NAME

pam_otpme - PAM module for OTPme authentication with offline login
support

# SYNOPSIS

    auth [success=1 default=ignore] pam_python.so pam_otpme.py [options...]

# DESCRIPTION

**pam_otpme** is a PAM module that authenticates users against an OTPme
realm. It is loaded via **pam_python.so** and supports online
authentication against the OTPme daemon as well as fully offline logins
using locally cached credentials.

When a user logs in online, the module can cache the user's token
credentials on the local host so that subsequent logins succeed even
when the OTPme server is unreachable. Offline caching must be enabled
individually for each token on the server:

    otpme-token enable_offline <token>

Offline credentials are protected by a key derivation function (KDF)
whose parameters can be tuned based on the strength of the user's
password.

In addition to offline tokens, the module supports *offline session
keeping*. When enabled for a token, the login session is cached
alongside the offline credentials and automatically restored on the next
offline login. Session keeping is enabled per token on the server:

    otpme-token enable_session_keep <token>

If the user has shares configured and auto-mount is enabled, shares are
mounted automatically when a session is restored from cache:

    otpme-user enable_auto_mount <user>

The module also supports hardware smartcards (e.g. YubiKey HMAC-SHA1)
and SSH key authentication via an SSH agent (e.g. YubiKey with GPG
applet combined with an OTPme **ssh** token).

# INSTALLATION

**pam_python.so** must be installed before **pam_otpme** can be used. On
Debian and Ubuntu install the distribution package:

    apt-get install libpam-python

The **pam_otpme.py** script is installed as part of OTPme and is
typically located in the OTPme Python package directory.

# OPTIONS

Options are passed as space-separated arguments after **pam_otpme.py**
on the PAM configuration line.

**cache_login_tokens**  
Cache login tokens that are configured for offline usage on the server.
This enables subsequent offline logins after a successful online
authentication.

**try_first_pass**  
Try to reuse the password supplied by a previously stacked PAM module.
If no password is available, prompt the user.

**use_first_pass**  
Use the password supplied by a previously stacked PAM module. Fail
immediately if no password is available.

**nullok**  
Allow authentication with an empty password.

**send_password=***auto\|false*  
Controls whether the user's password is sent to the OTPme server.
Values: **auto** - send the password only if the server requests it
(default); **false** - never send the password to the server (useful for
token types that do not require the password on the server side, e.g.
SSH tokens).

**use_smartcard=***auto\|true\|false*  
Controls smartcard usage (e.g. YubiKey HMAC-SHA1). Values: **auto** -
use a locally connected smartcard if one is detected (default);
**true** - require a smartcard, login without one is not possible;
**false** - ignore any connected smartcard.

**use_ssh_agent=***auto\|true\|false*  
Controls authentication via SSH key from an SSH agent (e.g. YubiKey with
GPG applet used together with an OTPme **ssh** token). Values:
**auto** - use the SSH agent if a suitable key is available (default);
**true** - require a valid SSH key from the agent, login without one is
not possible; **false** - do not use and do not start an SSH agent.

**start_ssh_agent=***auto\|true\|false*  
Controls whether an SSH agent is started at login. Values: **auto** -
decide based on public keys received from the server (default);
**true** - always start an SSH agent; **false** - never start an SSH
agent.

**unlock_via_offline_token**  
When set, screen unlock uses the locally cached offline token and does
not send an authentication request to the OTPme server.

**do_dot1x=***auto\|force*  
Perform 802.1x port authentication on login. Requires a Network Manager
dummy connection to be configured beforehand, for example:

<!-- -->

    nmcli connection add type ethernet con-name "dot1x-lan" ifname enp0s25 \
        802-1x.eap peap \
        802-1x.phase2-auth mschapv2 \
        802-1x.identity "user" \
        802-1x.password "pass"

> Values: **auto** - perform dot1x authentication only when the default
> gateway is unreachable (ICMP ping must be allowed); **force** - always
> perform dot1x authentication on login (restarts the network
> connection). The option **dot1x_token_type** must also be set.

**dot1x_token_type=***type*  
Token type used to generate the OTP for 802.1x port authentication.
Currently supported types: **yubikey_piv** and **password**.

**dot1x_timeout=***seconds*  
Number of seconds to wait for the 802.1x port authentication to
complete.

**offline_key_func=***func***\[;***opt***=***val***,...\]**  
Key derivation function used to encrypt the locally cached offline
token. The function name and its options are separated by **;**,
individual options by **,**, and key/value pairs by **:**. The only
supported function is **Argon2_i**. Available options: **iterations** -
number of iterations (default: 3); **min_mem** - minimum memory in KiB
(default: 65536); **max_mem** - maximum memory in KiB (default: 262144);
**threads** - number of threads (default: 4). Example:

<!-- -->

    offline_key_func=Argon2_i;min_mem:65536,max_mem:262144,iterations:6,threads:4

**check_offline_pass_strength=***policy***;***score***:***iterations***\[,...\]**  
Dynamically adjust the number of KDF iterations based on the strength of
the user's password. A weaker password receives more iterations; a
stronger password needs fewer. The first parameter specifies the OTPme
password policy used to calculate the strength score. Use **auto** to
use the policy assigned to the host. The second parameter (after **;**)
is a comma-separated list of *score***:***iterations* pairs that map a
strength score to a number of KDF iterations. Example:

<!-- -->

    check_offline_pass_strength=password_strength;0:6,1:6,2:6,3:5,4:5,5:5,6:3,7:3,8:3,9:3,10:3

**offline_greeting**  
Display a greeting message after a successful offline login.

**online_greeting**  
Display a greeting message after a successful online login.

**message_timeout=***seconds*  
Duration in seconds for which PAM messages are displayed. Default:
**2**.

**show_errors**  
Show OTPme-specific login error messages to the user via the PAM
conversation interface.

**connect_timeout=***seconds*  
Timeout in seconds when establishing a connection to the OTPme server.
Default: **3**.

**connection_timeout=***seconds*  
Timeout in seconds when waiting for a response from the OTPme server.
Default: **30**.

**create_home**  
Create the user's home directory on first login if it does not exist.

**home_skel=***path*  
Path to a skeleton directory used when creating a new home directory.
Requires **create_home**.

**debug**  
Enable verbose debug logging.

# EXAMPLES

A typical PAM entry that enables offline caching, smartcard and SSH
agent support, adaptive KDF iterations and debug output:

    auth [success=1 default=ignore] pam_python.so pam_otpme.py \
        try_first_pass \
        cache_login_tokens \
        use_smartcard=auto \
        use_ssh_agent=auto \
        offline_key_func=Argon2_i;min_mem:65536,max_mem:262144,iterations:6,threads:4 \
        check_offline_pass_strength=password_strength;0:6,1:6,2:6,3:5,4:5,5:5,6:3,7:3,8:3,9:3,10:3 \
        debug

A minimal entry for online-only authentication:

    auth [success=1 default=ignore] pam_python.so pam_otpme.py try_first_pass

# FILES

*/var/cache/otpme/offline/*  
Directory where offline token credentials and cached login sessions are
stored.

# SEE ALSO

**otpme-tool**(1), **otpme.conf**(5), **pam**(7), **pam_python**(8)

# AUTHOR

the2nd \<the2nd@otpme.org\>

# NOTE

This manual page was created with AI assistance.

# COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
