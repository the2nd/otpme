# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
""" The login records of a session, where every login writes them.

A shell handed out by a remote access job is a login on the host, and it
belongs where the other logins are: "last" reads /var/log/wtmp and says
who was logged in and for how long. A session that is not in there is
one nobody can account for afterwards.

Two things about a record decide how it reads, and both were measured
rather than reasoned about:

    The pid is the pid of the shell. "last" asks whether that process is
    still alive, and that is how it tells a session that is running
    ("still logged in") from one whose end was never written ("gone - no
    logout"). Nothing else in the file says it.

    The shape of a record is the struct utmp of glibc and not ours to
    choose. A record of the wrong shape does not fail -- it goes in and
    makes the login history of the host unreadable.

The records are appended by updwtmp() of the C library, which writes the
record it is given to the file it is given, and does the locking. It is
in libc.so.6 since glibc 2.34 and in libutil.so.1 before that; both are
asked for.

Not login() of the C library, although that one would write utmp as
well, which is what "who" reads: it fills in the terminal of the process
that calls it and its pid, over whatever the record said. In a job
runner there is no terminal, so what went into the file was four bytes
of something else where the terminal belongs, and the pid of the runner
instead of the shell. Writing utmp without it means finding the record
of a line and replacing it in a file every other login writes too --
worth doing for "who", and its own piece of work.
"""
import os
import time
import fcntl
import ctypes
import struct
import ctypes.util

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import config

from otpme.lib.exceptions import *

# Where the login history of the host lives.
WTMP_FILE = "/var/log/wtmp"

# struct utmp of glibc, 384 bytes on a 64 bit system:
#
#   short ut_type        at 0, with two bytes of padding behind it
#   pid_t ut_pid         at 4
#   char  ut_line[32]    at 8     the terminal, without /dev/
#   char  ut_id[4]       at 40    the last four of the terminal
#   char  ut_user[32]    at 44
#   char  ut_host[256]   at 76    where the login came from
#   short ut_exit[2]     at 332   unused here
#   int32 ut_session     at 336   unused here
#   int32 tv_sec         at 340   32 bit, even on a 64 bit system
#   int32 tv_usec        at 344
#   int32 ut_addr_v6[4]  at 348   the address of the peer, unused here
#   char  unused[20]     at 364
RECORD = struct.Struct("<hxxi32s4s32s256s4xiii16x20x")

# What a record says it is: a session and the end of one.
USER_PROCESS = 7
DEAD_PROCESS = 8

# Linux asks the master side of a terminal for its number with this.
TIOCGPTN = 0x80045430

# Which user a process is the login session of, as the kernel audit
# keeps it. Written once per session by whatever logs a user in --
# pam_loginuid does it for every other login path on the host.
LOGINUID_FILE = "/proc/self/loginuid"

# The library that holds updwtmp(), once it has been found.
_libc = None


def get_libc():
    """ The C library, or None where it has no updwtmp(). """
    global _libc
    if _libc is not None:
        return _libc
    logger = config.logger
    for name in ("c", "util"):
        path = ctypes.util.find_library(name)
        if not path:
            continue
        try:
            library = ctypes.CDLL(path, use_errno=True)
        except Exception as e:
            log_msg = _("Failed to load {path}: {error}", log=True)[1]
            log_msg = log_msg.format(path=path, error=e)
            logger.debug(log_msg)
            continue
        if not hasattr(library, "updwtmp"):
            continue
        # The file to append to and the record to append. It answers
        # nothing: whether the file could be written is not something it
        # says.
        library.updwtmp.argtypes = [ctypes.c_char_p,
                                    ctypes.POINTER(ctypes.c_char)]
        library.updwtmp.restype = None
        _libc = library
        return _libc
    log_msg = _("Found no updwtmp(), not writing login records.", log=True)[1]
    logger.warning(log_msg)
    return None


def terminal_name(master_fd):
    """ The name of the terminal behind this master, without /dev/.

    "pts/5", which is what a record holds and what "last" shows. Asked
    of the master because that is the side we keep: pty.fork() hands the
    other one to the child and nothing of it is left here.
    """
    packed = fcntl.ioctl(master_fd, TIOCGPTN, struct.pack("I", 0))
    number = struct.unpack("I", packed)[0]
    return f"pts/{number}"


def build_record(line, user, host, pid, when=None,
    record_type=USER_PROCESS):
    """ One record, as the file holds them.

    What is too long for a field is cut: a record of the right size is
    worth more than a name in full, because one byte too many puts every
    field behind it in the wrong place.
    """
    line = line.encode()[:31]
    return RECORD.pack(
                    record_type,
                    pid,
                    line,
                    # The way login(1) and sshd fill it: the last four
                    # characters of the terminal.
                    line[-4:],
                    user.encode()[:31],
                    host.encode()[:255],
                    0,
                    int(when if when is not None else time.time()),
                    0,
                    )


def write_record(record, wtmp_file=None):
    """ Append one record, or say in the log that it did not happen.

    A session is not failed because its line in "last" is missing, so
    nothing is raised here. Nor is the file made where there is none: a
    host without /var/log/wtmp keeps no login history, and starting one
    would be a decision about that host.

    <wtmp_file> is looked up when it is used and not when this is
    defined, so WTMP_FILE can be set to something else at runtime --
    which is how a test lets a whole session write for real.
    """
    logger = config.logger
    if wtmp_file is None:
        wtmp_file = WTMP_FILE
    libc = get_libc()
    if libc is None:
        return False
    if not os.path.exists(wtmp_file):
        log_msg = _("Not writing a login record, there is no {wtmp_file}.", log=True)[1]
        log_msg = log_msg.format(wtmp_file=wtmp_file)
        logger.debug(log_msg)
        return False
    try:
        buffer = ctypes.create_string_buffer(record, len(record))
        libc.updwtmp(wtmp_file.encode(), buffer)
    except Exception as e:
        log_msg = _("Failed to write a login record: {error}", log=True)[1]
        log_msg = log_msg.format(error=e)
        logger.warning(log_msg)
        return False
    return True


def set_login_uid(uid, loginuid_file=None):
    """ Say which user this process is the login session of.

    The kernel keeps one uid per process that does not change when the
    process changes user and that everything it starts inherits. It is
    set by whatever logs a user in -- pam_loginuid does it for a login
    over ssh, on a console and through su.

    "last" reads it: it takes the pid of a record, looks up the login uid
    of that process and calls the session gone when the two do not name
    the same user (is_phantom() of util-linux). A daemon started by
    systemd has none, and the shell of a session inherits that, so
    without this every running session reads as "gone - no logout" --
    measured against one and the same record, with a live pid, on a host
    whose daemons are services.

    Nothing is said about a failure, here or in the log: this runs in the
    child of pty.fork(), where the error output is the terminal of the
    session and a line written there lands in the shell of whoever is
    logged in. The kernel refuses to change a uid that is already set
    unless the caller may audit, so a host that sets it some other way
    first keeps what it has -- which is the right outcome either way.

    Writing it needs root, so it happens before the privileges of the
    session are dropped.
    """
    if loginuid_file is None:
        loginuid_file = LOGINUID_FILE
    try:
        with open(loginuid_file, "w") as fd:
            fd.write(str(uid))
    except Exception:
        return False
    return True


def login(line, user, host, pid, wtmp_file=None):
    """ Write that a session on this terminal began. """
    record = build_record(line, user, host, pid,
                        record_type=USER_PROCESS)
    return write_record(record, wtmp_file=wtmp_file)


def logout(line, pid, wtmp_file=None):
    """ Write that the session on this terminal ended.

    No user and no host: that is how the end of a session is written,
    and "last" reads it as the end of the one that began on the same
    terminal. Without it the session stands there as still logged in for
    as long as its pid is alive, and as "gone - no logout" afterwards.
    """
    record = build_record(line, "", "", pid,
                        record_type=DEAD_PROCESS)
    return write_record(record, wtmp_file=wtmp_file)
