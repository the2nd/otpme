# OTPME(1)

## NAME

otpme - global options for OTPme management commands

## DESCRIPTION

All OTPme management commands (otpme-user, otpme-token, otpme-client, etc.) share a common set of global options described here. For a conceptual overview of the OTPme system, see
[otpme(7)](otpme.7.md).

## GLOBAL OPTIONS

### Connection Options

**-r *realm***
:   Connect to a specific realm.

**-s *site***
:   Connect to a specific site.

**-t *timeout***
:   Connect timeout in seconds.

**-tt *timeout***
:   Connection timeout in seconds.

**-c *config_file***
:   Use alternative config file.

**--no-dns**
:   Do not resolve OTPme site address via DNS.

**--use-dns**
:   Resolve OTPme site address via DNS.

**--login-no-dns**
:   Do not resolve OTPme login point via DNS.

**--login-use-dns**
:   Resolve OTPme login point via DNS.

### Authentication Options

**--use-ssh-agent [*y|n*]**
:   Use ssh-agent for authentication.

**--use-smartcard [*y|n*]**
:   Use smartcard for authentication.

**--stdin-pass**
:   Read passphrase from stdin.

**--auth-token *token***
:   Emulate login with given token in API mode.

### Communication Options

**--socket**
:   Use mgmtd socket.

**--api**
:   Use direct API calls instead of connecting to a daemon.

### General Options

**--type *object_type***
:   Object type to act on (e.g. token type).

**-f**
:   Do not ask any user questions.

**--print-raw-sign-data**
:   Print raw data to sign instead of sign info.

**--version**
:   Show version.

**-v**
:   Enable verbose mode.

### Debug Options

**-d**
:   Enable debug mode. Multiple 'd' will increase debug level.

**-da**
:   Debug function cache adds.

**-dA**
:   Enable debug of transactions.

**-db**
:   Print when objects are read from backend.

**-dc**
:   Print when objects are read from cache.

**-dr**
:   Print file reads.

**-dw**
:   Print file writes.

**-dC**
:   Enable debug logging for client messages.

**-dD**
:   Do not go to background and log to stdout.

**-de**
:   Print tracebacks.

**-dee**
:   Raise debug exceptions.

**-dh**
:   Debug function cache hits.

**-dL**
:   Debug locks.

**-dm**
:   Print loading of OTPme modules.

**-dM**
:   Enable function/method call tracing.

**-dN**
:   Debug network packets.

**-dt**
:   Enable timestamps in debug output.

**-dP**
:   Enable profiling via cProfile.

**-dT**
:   Print warning if function/method call takes longer than --debug-timing-limit.

**-dTT**
:   Print timing result after method finishes.

**-dTTT**
:   Print warning each time method call gets slower.

**--color-logs**
:   Use colored logs.

**--log-filter *daemon1,daemon2***
:   Only print log messages for the given daemons.

**--debug-daemons *daemon1,daemon2***
:   Enable debug stuff only for the given daemons.

**--debug-users *user1,user2***
:   Enable debug stuff only for the given users.

**--debug-func-names *method1,method2***
:   Enable timing for given functions only.

**--debug-func-start *method1,method2***
:   Start timing on method call.

**--debug-func-caches *cache1,cache2***
:   Enable debug stuff only for the given function caches.

**--debug-timing-limit *seconds***
:   Print warning if function/method call takes longer than given seconds.

**--debug-counter-limit *call_count***
:   Print warning if function/method is called more than given count.

**--debug-profile-sort *cumtime|ncalls|tottime***
:   Statistic output sorting.

### Job Options

**--lock-timeout *seconds***
:   Lock timeout in seconds when starting jobs.

**--lock-wait-timeout *seconds***
:   Lock wait timeout in seconds when starting jobs.

**--lock-ignore-changed-objects**
:   Ignore if an object changed while waiting for lock.

**--job-timeout *seconds***
:   Job timeout.

### Advanced Options

**--enable-typing**
:   Enable Python type checking.

**--disable-locking**
:   Disable locking in API mode (use with caution).

## SEE ALSO

[otpme(7)](otpme.7.md),
[otpme-accessgroup(1)](otpme-accessgroup.md),
[otpme-ca(1)](otpme-ca.md),
[otpme-client(1)](otpme-client.md),
[otpme-dictionary(1)](otpme-dictionary.md),
[otpme-group(1)](otpme-group.md),
[otpme-host(1)](otpme-host.md),
[otpme-node(1)](otpme-node.md),
[otpme-policy(1)](otpme-policy.md),
[otpme-pool(1)](otpme-pool.md),
[otpme-realm(1)](otpme-realm.md),
[otpme-resolver(1)](otpme-resolver.md),
[otpme-role(1)](otpme-role.md),
[otpme-script(1)](otpme-script.md),
[otpme-share(1)](otpme-share.md),
[otpme-site(1)](otpme-site.md),
[otpme-token(1)](otpme-token.md),
[otpme-tool(1)](otpme-tool.md),
[otpme-unit(1)](otpme-unit.md),
[otpme-user(1)](otpme-user.md)

## AUTHOR

the2nd <the2nd@otpme.org>

## NOTE

This manual page was created with AI assistance.

## COPYRIGHT

Copyright © 2014-2025 the2nd. License: GPLv3
