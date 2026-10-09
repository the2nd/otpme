# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
""" The SSH server side of a remote access job.

A remote_access job names one SSH public key, and whoever holds the
private half of it gets a shell on this host. The host is the SSH
server; it speaks SSH over a socket somebody else hands it, so a broker
can carry the session without being able to read it.

Not the sshd of the host on purpose. Going through it would put the
decision back into sshd_config, authorized_keys and PAM -- a second way
in, beside the signed job, and a root shell would need PermitRootLogin.
Here the one key of the job is the only key there is, for one session,
and then this is over.

Which user the shell runs as comes from the job and never from the
client: the name a client sends in its SSH userauth request is not
looked at. The job is signed, the request is not.

Paramiko does the crypto of the authentication. check_auth_publickey()
below says which key is acceptable; whether the client actually holds
it is decided by paramiko, which verifies the signature and turns the
answer into AUTH_FAILED when it does not verify (auth_handler.py, the
verify_ssh_sig() call right after ours).
"""
import io
import os
import re
import pty
import pwd
import time
import hmac
import json
import fcntl
import base64
import select
import signal
import socket
import struct
import logging
import termios
import threading

import paramiko

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import wtmp
from otpme.lib import config
from otpme.lib import rendezvous

from otpme.lib.exceptions import *

logger = config.logger

# How long the client has to get through the handshake and the
# authentication. A session that nobody is at the other end of should
# not sit here holding the job.
BANNER_TIMEOUT = 15
HANDSHAKE_TIMEOUT = 30
AUTH_TIMEOUT = 30
# How long we wait for the client to ask for its shell once it is in.
SHELL_TIMEOUT = 30
# How long we wait for the client to hang up at the end of a session. It
# closes first on purpose, see GentlyClosed.
CLOSE_TIMEOUT = 10
# How often we ask the client whether it is still there. Nothing limits
# how long a session may last -- there is no length at which a shell
# somebody is working in becomes wrong, and the time to live of the job
# says until when a shell may be asked for, not how long it may be used.
# What has to end is a session whose client is gone without saying so,
# and this is what notices: the question travels through the broker, so
# it is the client that answers it and not the broker.
KEEPALIVE_INTERVAL = 30
# The largest chunk moved in one go between the channel and the pty.
IO_CHUNK = 65536
# What a terminal name may look like. It reaches the environment of the
# shell, so it is not taken as it comes.
TERM_RE = r'^[a-zA-Z0-9][a-zA-Z0-9._+-]{0,63}$'
# The environment the client may ask for, and what it may look like.
# Only the language: the shell here runs as root, and a variable like
# LD_PRELOAD or PATH would be a way in for whoever reaches this channel.
# A locale is what a terminal needs to show anything but ASCII -- in the
# C locale an umlaut typed into the shell never arrives as one.
ENV_NAME_RE = r'^(LANG|LC_[A-Z]+)$'
ENV_VALUE_RE = r'^[a-zA-Z0-9][a-zA-Z0-9._@-]{0,63}$'
# What the shell gets where the client asked for no language at all. A
# pty without a UTF-8 locale mangles every character that is not ASCII,
# and that is worse than a language nobody asked for.
DEFAULT_LANG = "C.UTF-8"
# The largest window we accept. A client that asks for more gets what
# fits; the numbers go into an ioctl.
MAX_WINDOW = 65535
# What a host says before it speaks SSH, to vouch for the key of this
# session. The tag is in the signed data as well, so a signature made
# for something else cannot be read as one of these.
VOUCH_TAG = "OTPME-RAC-VOUCH-1"
# And what it signs once the session stands, to show that it is the end
# of it and not a party carrying it, see build_session_bind(). Its own
# tag for the same reason the vouch has one.
BIND_TAG = "OTPME-RAC-BIND-1"
# An RSA signature of a 4096 bit key, base64, with the key blob and
# some JSON around it. Generous, and bounded: what follows the line is
# the SSH handshake, and a host that never sends a newline must not
# keep us reading for ever.
MAX_VOUCH_LEN = 16384


def generate_host_key():
    """ An SSH host key for one session.

    Ephemeral on purpose: nothing here is meant to outlive the session,
    and a key that is thrown away cannot be stolen later. What makes it
    trustworthy for the client is not that it stays the same but that
    the host vouches for it with the key it was joined with -- that is
    the business of whoever hands us the socket, see the broker.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    private_key = ed25519.Ed25519PrivateKey.generate()
    openssh = private_key.private_bytes(serialization.Encoding.PEM,
                                    serialization.PrivateFormat.OpenSSH,
                                    serialization.NoEncryption())
    return paramiko.Ed25519Key.from_private_key(io.StringIO(openssh.decode()))


def get_vouch_data(job_uuid, host_key):
    """ What the host signs to vouch for the key of this session.

    The job and the key together, and both of them whole. The job is
    in it so a signature cannot be moved to another session, and the
    key is in it because that is what is being vouched for. Built the
    same way on both sides, so a byte more or less on either is a
    signature that does not verify.
    """
    key_blob = base64.b64encode(host_key.asbytes()).decode()
    return f"{VOUCH_TAG}:{job_uuid}:{key_blob}"


def build_host_vouch(job_uuid, host_key, private_key):
    """ The line a host sends before it speaks SSH.

    The session key of an SSH server is one the client has never seen
    and cannot look up: the job was signed before the host picked it.
    So the host vouches for it with the key it was joined with, whose
    public half is on its object in the tree -- and the client, which
    has that object, can hold one against the other.

    Sent before the SSH banner and not in it: a banner reaches the
    client in the middle of the authentication, by which time it has
    accepted the key already. This is the first thing on the wire, so
    nothing is accepted before it has been read.
    """
    from otpme.lib.encryption.rsa import RSAKey
    key = RSAKey(key=private_key)
    vouch_data = get_vouch_data(job_uuid, host_key)
    signature = key.sign(message=vouch_data, encoding="base64")
    vouch = {
            'job'       : job_uuid,
            'host_key'  : base64.b64encode(host_key.asbytes()).decode(),
            'signature' : signature,
            }
    line = base64.b64encode(json.dumps(vouch).encode()).decode()
    return f"{VOUCH_TAG} {line}\n".encode()


def verify_host_vouch(line, job_uuid, host_public_key):
    """ Whether this is the host the job was for.

    Returns the SSH host key the host vouched for, which is the one
    the session has to be with. Anything else, and somebody other than
    the host we asked for is at the other end -- a broker that spliced
    us to the wrong one, for instance.
    """
    from otpme.lib.encryption.rsa import RSAKey
    if isinstance(line, bytes):
        line = line.decode(errors="replace")
    line = line.strip()
    tag, _found, payload = line.partition(" ")
    if tag != VOUCH_TAG or not payload:
        msg = _("The other end did not say who it is.")
        raise OTPmeException(msg)
    try:
        vouch = json.loads(base64.b64decode(payload).decode())
        host_key_blob = base64.b64decode(vouch['host_key'])
        signature = vouch['signature']
        vouched_job = vouch['job']
    except Exception as e:
        msg = _("Unreadable vouch: {error}")
        msg = msg.format(error=e)
        raise OTPmeException(msg) from e
    # The job first: a signature that is good for another session is
    # good for nothing here, and saying so is cheaper than verifying.
    if vouched_job != job_uuid:
        msg = _("The other end vouched for another session: {job}")
        msg = msg.format(job=vouched_job)
        raise OTPmeException(msg)
    key = RSAKey(key=host_public_key)
    vouch_data = f"{VOUCH_TAG}:{job_uuid}:{vouch['host_key']}"
    try:
        verified = key.verify(signature=signature,
                            message=vouch_data,
                            encoding="base64")
    except Exception as e:
        msg = _("Bad vouch: {error}")
        msg = msg.format(error=e)
        raise OTPmeException(msg) from e
    if not verified:
        msg = _("The other end is not the host this job was for.")
        raise OTPmeException(msg)
    return host_key_blob


def read_host_vouch(sock, timeout=None):
    """ The vouch line, and nothing of what comes after it.

    Read one byte at a time up to the newline: what follows is the SSH
    handshake, and reading a single byte of that here would take it
    away from the library that has to see it.

    An end that says nothing at all ends up here as well, and not as a
    TimeoutError of its own: silence and a connection that went away
    are the same answer to the one question asked here.

    <timeout> is looked up when it is used and not when this is defined,
    so BANNER_TIMEOUT can be set to something else at runtime.
    """
    if timeout is None:
        timeout = BANNER_TIMEOUT
    line = b""
    sock.settimeout(timeout)
    while len(line) < MAX_VOUCH_LEN:
        try:
            data = sock.recv(1)
        except TimeoutError:
            break
        if not data:
            break
        if data == b"\n":
            return line
        line += data
    msg = _("No vouch from the other end.")
    raise OTPmeException(msg)


def get_bind_data(job_uuid, session_id):
    """ What the host signs to show it is the end of this session.

    The id of the SSH session, which is the exchange hash of its key
    exchange: hash(V_C || V_S || I_C || I_S || K_S || e || f || K).
    The last of those is the shared secret of the Diffie-Hellman, so
    only the two ends of that exchange can work this value out -- a
    party that forwards the bytes of somebody else's key exchange sees
    everything in there but K, and so never learns the hash.

    Built the same way on both sides and never sent: the whole of what
    this is worth rests on the client holding it against the id of its
    own session, not against a value somebody handed it. A host could
    sign any id it likes with its own key.

    Its own tag, so a vouch cannot be read as a binding or the other
    way round, and the job in it, so a binding cannot be moved to
    another session.
    """
    return f"{BIND_TAG}:{job_uuid}:{base64.b64encode(session_id).decode()}"


def build_session_bind(job_uuid, session_id, private_key):
    """ The line a host sends once the session stands.

    It answers the one question the vouch leaves open. The vouch says
    which SSH host key this session is with, signed by the key the host
    was joined with -- and a host that holds that key may name any SSH
    host key at all, including one belonging to somebody else. So a
    host whose root is somebody else's can vouch for a third host's SSH
    key and splice the connection through to it: the key exchange then
    happens between the client and that third host, everything the
    client checks holds, and it is working on a machine it never asked
    for.

    What that forwarding host cannot do is know the id of the session
    it is only carrying. So it is asked for it.
    """
    from otpme.lib.encryption.rsa import RSAKey
    key = RSAKey(key=private_key)
    bind_data = get_bind_data(job_uuid, session_id)
    signature = key.sign(message=bind_data, encoding="base64")
    return f"{BIND_TAG} {signature}\n".encode()


def verify_session_bind(line, job_uuid, session_id, host_public_key):
    """ Whether the host is the end of this session and not in the
    middle of it.

    <session_id> is ours, read from our own transport. Nothing of it
    comes off the wire; only the signature does.
    """
    from otpme.lib.encryption.rsa import RSAKey
    if isinstance(line, bytes):
        line = line.decode(errors="replace")
    line = line.strip()
    tag, _found, signature = line.partition(" ")
    if tag != BIND_TAG or not signature:
        msg = _("The other end did not say it is the end of this session.")
        raise OTPmeException(msg)
    key = RSAKey(key=host_public_key)
    bind_data = get_bind_data(job_uuid, session_id)
    try:
        verified = key.verify(signature=signature,
                            message=bind_data,
                            encoding="base64")
    except Exception as e:
        msg = _("Bad session binding: {error}")
        msg = msg.format(error=e)
        raise OTPmeException(msg) from e
    if not verified:
        msg = _("The host is not the end of this session, only on the way.")
        raise OTPmeException(msg)


def read_session_bind(channel, timeout=None):
    """ The binding line off the channel, and nothing after it.

    One byte at a time up to the newline, the way the vouch is read:
    what follows is the shell, and a byte of that taken here is a byte
    the session never sees.

    The timeout is put back afterwards, because what reads the channel
    next is the session itself: a channel left with a timeout on it
    hands the session a TimeoutError instead of waiting, and the
    session reads that as a far end that is gone.

    A host that holds the channel open and says nothing is the one this
    is really for -- a party that only carries the session cannot work
    the id out, so it has nothing to send. That is a refusal like any
    other here, not a TimeoutError for the caller to make sense of
    (paramiko raises PipeTimeout, which is a TimeoutError).

    <timeout> is looked up when it is used and not when this is defined,
    so BANNER_TIMEOUT can be set to something else at runtime.
    """
    if timeout is None:
        timeout = BANNER_TIMEOUT
    line = b""
    before = channel.gettimeout()
    channel.settimeout(timeout)
    try:
        while len(line) < MAX_VOUCH_LEN:
            try:
                data = channel.recv(1)
            except TimeoutError:
                break
            if not data:
                break
            if data == b"\n":
                return line
            line += data
    finally:
        channel.settimeout(before)
    msg = _("No session binding from the host.")
    raise OTPmeException(msg)


def get_user_entry(user):
    """ The passwd entry of the user the shell is to run as. """
    try:
        return pwd.getpwnam(user)
    except KeyError as err:
        msg = _("No such user on this host: {user}")
        msg = msg.format(user=user)
        raise OTPmeException(msg) from err


def set_window_size(fd, columns, rows):
    """ Tell the terminal how large it is. """
    columns = max(1, min(int(columns), MAX_WINDOW))
    rows = max(1, min(int(rows), MAX_WINDOW))
    winsize = struct.pack("HHHH", rows, columns, 0, 0)
    try:
        fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)
    except OSError:
        # The shell is gone. Nothing to resize, and nothing to say.
        pass


class RemoteAccessServer(paramiko.ServerInterface):
    """ What this host answers to an SSH client.

    Everything is refused but the one thing the job asked for: one
    session, on a key this host lets in, with a shell or the command
    the job named.

    Which keys those are comes from outside, as <allowed_keys>. Either
    the one key a job named, or this host's own authorized_keys for the
    user the shell runs as -- see serve_session().

    Derived from ServerInterface and not written from scratch on
    purpose: what it does not know it refuses, so a question paramiko
    learns to ask tomorrow is answered with no by a class that has
    never heard of it.
    """
    def __init__(self, allowed_keys, user, command=None, x_logger=None):
        if not allowed_keys:
            msg = _("A remote access session needs a key to let in.")
            raise OTPmeException(msg)
        self.allowed_keys = list(allowed_keys)
        self.user = user
        # A command the job named is a forced command: the client may
        # ask for a shell or for something else, it gets this.
        self.command = command
        self.logger = x_logger or logger
        self.channel_id = None
        self.term = "xterm"
        self.columns = 80
        self.rows = 24
        self.master_fd = None
        self.shell_event = threading.Event()
        self.auth_key = None
        # What the client asked to have in the environment of the shell.
        # Only what ENV_NAME_RE allows ever gets in here.
        self.environment = {}

    # ---- who gets in ------------------------------------------------

    def get_allowed_auths(self, username):
        return "publickey"

    def check_auth_none(self, username):
        return paramiko.AUTH_FAILED

    def check_auth_password(self, username, password):
        return paramiko.AUTH_FAILED

    def check_auth_interactive(self, username, submethods):
        return paramiko.AUTH_FAILED

    def check_auth_interactive_response(self, responses):
        return paramiko.AUTH_FAILED

    def check_auth_gssapi_with_mic(self, username, gss_authenticated=None,
        cc_file=None):
        return paramiko.AUTH_FAILED

    def check_auth_gssapi_keyex(self, username, gss_authenticated=None,
        cc_file=None):
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        """ Whether this is a key this host lets in.

        The whole key as it goes over the wire, which carries its type
        as its first string -- so a key of one type cannot pass as the
        same bytes under another. Compared in constant time, because
        the answer is sent back either way, and against every allowed
        key rather than until the first match, so the answer takes the
        same time whichever key it was.

        <username> is not looked at. The user the shell runs as comes
        from the signed job; what a client writes in its request is not
        signed by anybody.

        A client offers the keys it has one after another, the way ssh
        does, so a refusal here is the ordinary course of a session and
        not a thing to warn about. What got in is logged where the
        session is opened.
        """
        offered = key.asbytes()
        allowed = False
        for x_key in self.allowed_keys:
            if hmac.compare_digest(offered, x_key):
                allowed = True
        if not allowed:
            log_msg = _("Remote access: key not allowed here ({fingerprint}).", log=True)[1]
            log_msg = log_msg.format(fingerprint=key.get_fingerprint().hex())
            self.logger.debug(log_msg)
            return paramiko.AUTH_FAILED
        self.auth_key = key
        return paramiko.AUTH_SUCCESSFUL

    # ---- what may be asked for --------------------------------------

    def check_channel_request(self, kind, chanid):
        """ One session and nothing else. """
        if kind != "session":
            return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        if self.channel_id is not None:
            # A job is one session. A second one would run beside the
            # first with nobody watching it.
            return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        self.channel_id = chanid
        return paramiko.OPEN_SUCCEEDED

    def check_channel_pty_request(self, channel, term, width, height,
        pixelwidth, pixelheight, modes):
        if isinstance(term, bytes):
            term = term.decode(errors="replace")
        if re.match(TERM_RE, term or ""):
            self.term = term
        self.columns = width
        self.rows = height
        return True

    def check_channel_shell_request(self, channel):
        self.shell_event.set()
        return True

    def check_channel_exec_request(self, channel, command):
        """ A command the client wants to run.

        Where the job named one, that is what runs -- the client asking
        for something else does not change what was signed. Where it
        named none, the client picks.
        """
        if self.command is None:
            if isinstance(command, bytes):
                command = command.decode(errors="replace")
            self.command = command
        self.shell_event.set()
        return True

    def check_channel_window_change_request(self, channel, width, height,
        pixelwidth, pixelheight):
        self.columns = width
        self.rows = height
        if self.master_fd is not None:
            set_window_size(self.master_fd, width, height)
        return True

    def check_channel_env_request(self, channel, name, value):
        """ A variable the client wants in the environment of the shell.

        Only the language, and only where it looks like one. The rest of
        the environment is ours: a shell that takes PATH or LD_PRELOAD
        from whoever reaches this channel is a shell that runs their
        code as the user it was opened for.
        """
        if isinstance(name, bytes):
            name = name.decode(errors="replace")
        if isinstance(value, bytes):
            value = value.decode(errors="replace")
        if not re.match(ENV_NAME_RE, name or ""):
            return False
        if not re.match(ENV_VALUE_RE, value or ""):
            return False
        self.environment[name] = value
        return True

    # ---- and what may not -------------------------------------------

    def check_channel_subsystem_request(self, channel, name):
        return False

    def check_channel_x11_request(self, channel, single_connection,
        auth_protocol, auth_cookie, screen_number):
        return False

    def check_channel_forward_agent_request(self, channel):
        return False

    def check_channel_direct_tcpip_request(self, chanid, origin, destination):
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_port_forward_request(self, address, port):
        return False

    def check_global_request(self, kind, msg):
        return False


def start_shell(server, user_entry):
    """ A shell on a terminal of its own, as the user the job named.

    Returns the pid of the child and the master side of the terminal.
    """
    pid, master_fd = pty.fork()
    if pid == 0:
        # The child. Nothing here may return: every way out is an exec
        # or an exit, or the child would go on as a copy of the daemon.
        try:
            os.chdir(user_entry.pw_dir)
        except OSError:
            os.chdir("/")
        # This process is the login session of that user from here on,
        # and so is the shell it becomes. Before the privileges go,
        # because setting it needs them (lib/wtmp.set_login_uid).
        wtmp.set_login_uid(user_entry.pw_uid)
        if os.getuid() == 0 and user_entry.pw_uid != 0:
            os.initgroups(user_entry.pw_name, user_entry.pw_gid)
            os.setgid(user_entry.pw_gid)
            os.setuid(user_entry.pw_uid)
        shell = user_entry.pw_shell or "/bin/sh"
        environment = {
                    'HOME'      : user_entry.pw_dir,
                    'USER'      : user_entry.pw_name,
                    'LOGNAME'   : user_entry.pw_name,
                    'SHELL'     : shell,
                    'TERM'      : server.term,
                    'PATH'      : "/usr/local/bin:/usr/bin:/bin",
                    }
        # The language of whoever opened the session, so a terminal shows
        # what is typed into it. Added last but it cannot overwrite any
        # of the above: only LANG and LC_* ever get this far.
        environment.update(server.environment)
        if 'LANG' not in environment:
            environment['LANG'] = DEFAULT_LANG
        try:
            if server.command:
                os.execve(shell, [shell, "-c", server.command], environment)
            # The leading "-" is how a shell is told it is a login
            # shell, and it is the only way to tell it.
            argv0 = f"-{os.path.basename(shell)}"
            os.execve(shell, [argv0], environment)
        except Exception:
            os._exit(127)
        os._exit(127)
    return pid, master_fd


def why_ssh_gave_up(transport):
    """ What SSH made of the end of a session, as something to append.

    A transport that dies keeps the reason, and nothing else has it: what
    reaches the session itself is only that the socket was closed, which
    says nothing about what closed it. Empty where there is nothing to
    say.

    Whether the connection was torn away or simply ended is in that
    reason, because the socket was asked to tell them apart rather than
    report both as nothing (rendezvous.tell_a_break_from_an_end).
    """
    try:
        error = transport.get_exception()
    except Exception:
        return ""
    if not error:
        return ""
    return f"; ssh: {type(error).__name__}: {error}"


def write_all(fd, data):
    """ Write all of it, because os.write() may write some of it.

    A terminal takes what fits in its input buffer and says how much that
    was. What is typed is small enough that this is normally all of it,
    but a line pasted into a full buffer is not, and the rest of it would
    simply be gone.
    """
    while data:
        written = os.write(fd, data)
        data = data[written:]


def pump(channel, master_fd, deadline=None):
    """ Move bytes between the channel and the terminal until one ends.

    Returns what ended it. A session that is lost rather than closed ends
    it too: the job was to hand out a shell, and a shell that was handed
    out and then lost is not a job that failed. Without this, a client
    that went away came back as a traceback and a failed job, which says
    nothing about what happened and hides what did.
    """
    while True:
        timeout = 1.0
        if deadline is not None:
            left = deadline - time.time()
            if left <= 0:
                return "expired"
            timeout = min(timeout, left)
        try:
            readable = select.select([channel, master_fd], [], [], timeout)[0]
        except (OSError, ValueError):
            return "closed"
        if master_fd in readable:
            try:
                data = os.read(master_fd, IO_CHUNK)
            except OSError:
                # The shell is gone and took its terminal with it.
                return "shell"
            if not data:
                return "shell"
            try:
                channel.sendall(data)
            except Exception as e:
                return f"lost: {e}"
        if channel in readable:
            if channel.recv_ready():
                try:
                    data = channel.recv(IO_CHUNK)
                except Exception as e:
                    return f"lost: {e}"
                if not data:
                    return "client"
                try:
                    write_all(master_fd, data)
                except OSError:
                    # The shell is gone, and what was typed at it has
                    # nowhere to go.
                    return "shell"
            elif channel.eof_received:
                return "client"
        if not channel.get_transport().is_active():
            # The session is gone. Asked every round, because a channel
            # whose session has gone still says it has something to read
            # and then has neither data nor an end of file to give --
            # which is neither of the two things above, so without this
            # we sat here turning in circles while the shell waited for
            # input that could no longer reach it.
            return "lost"


def end_channel(channel):
    """ Tell the client the session is over.

    Closing the channel is what makes its recv() return nothing; the
    client would otherwise sit there until it gives up. Sent while the
    connection is still there, because closing the connection does not
    say it -- with a broker in between there is nobody to pass a
    half-close on, and the client would never learn that the shell had
    ended.
    """
    try:
        channel.close()
    except Exception:
        pass


class SSHLogRelay(logging.Handler):
    """ What SSH says about a session, into the log of that session.

    paramiko keeps a logger of its own, and in a job process nothing is
    listening to it -- so the one party that knows why a session ended
    was saying it into the dark. Only what it considers a problem is
    passed on: the rest of what it says is every packet.
    """
    def __init__(self, x_logger):
        super().__init__(level=logging.WARNING)
        self.x_logger = x_logger

    def emit(self, record):
        try:
            log_msg = _("Remote access session, ssh says: {said}", log=True)[1]
            log_msg = log_msg.format(said=record.getMessage())
            self.x_logger.warning(log_msg)
        except Exception:
            pass


class GentlyClosed(rendezvous.WaitedFor):
    """ A socket that does not take the end of a session with it.

    Waited for before it is called, which is what the base class is for:
    SSH reads the connection in a thread of its own while the shell's
    output is written to it, and a call that has to come back round for
    more while the other thread is inside takes the connection apart.

    Everything goes through to the socket underneath. Only the close is
    ours, because a plain one loses data: a socket closed while something
    is unread on the way in -- and there is always something, the far end
    keeps saying how much more it can take -- is closed with a reset, and
    a reset throws away both what of ours had not arrived yet and what had
    arrived at the far end unread. Measured on a session that put out two
    megabytes: a few hundred kilobytes of the end of it went missing.

    So the close says there is no more from here, which sends what is
    waiting, and then waits for the far end to go. The far end goes once
    it has everything, and after that nothing is left to lose.

    Wrapped around the socket rather than done where the session ends,
    because the session can end in more ways than one -- and the one that
    cost the most was SSH giving up on its own, where there was nothing
    to say that the socket was not finished with.
    """
    # What the kernel calls the states of a connection, so a report can
    # say the name rather than the number.
    TCP_STATES = {
                1:"established", 2:"syn-sent", 3:"syn-received",
                4:"fin-wait-1", 5:"fin-wait-2", 6:"time-wait",
                7:"closed", 8:"close-wait", 9:"last-ack", 10:"listening",
                11:"closing",
                }

    def __init__(self, sock, timeout=CLOSE_TIMEOUT):
        super().__init__(sock)
        self.timeout = timeout
        self.closed_gently = None
        # What the kernel thought of the connection the first time SSH
        # read nothing from it, see went_quiet().
        self.quiet_because = None
        self.read = 0

    def state(self):
        """ What the kernel calls this connection, in a word. """
        try:
            info = self.sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 1)
            return self.TCP_STATES.get(info[0], f"state {info[0]}")
        except (OSError, AttributeError, IndexError):
            return "cannot be asked"

    def went_quiet(self, what):
        """ Write down what the kernel thinks, the first time SSH does
        not get anything.

        SSH reads nothing and takes that for the end of the connection,
        which is the only thing it can do with it. Whether the
        connection had in fact ended is a question for the kernel, and
        asking it afterwards is too late -- by then we have closed it
        ourselves. So it is asked here, at the moment it happens.

        A connection the kernel still calls established, where SSH was
        told there is nothing more, is a connection that nobody ended.
        """
        if self.quiet_because is not None:
            return
        self.quiet_because = (f"{what} after {self.read} bytes, "
                            f"the kernel calls it {self.state()}")

    def why(self, error):
        """ What OpenSSL calls it, which is more than what it says.

        The text of it is the same for a connection that ended without
        saying goodbye and for one whose stream no longer made sense.
        The reason tells them apart: UNEXPECTED_EOF_WHILE_READING is the
        first, anything else is the second.
        """
        reason = getattr(error, "reason", None)
        library = getattr(error, "library", None)
        said = f"{type(error).__name__}: {error}"
        if reason or library:
            said = f"{said} [{library}: {reason}]"
        return said

    def recv(self, *args, **kwargs):
        try:
            data = super().recv(*args, **kwargs)
        except TimeoutError:
            raise
        except OSError as e:
            self.went_quiet(self.why(e))
            raise
        if not data:
            self.went_quiet("a read of nothing")
        self.read += len(data)
        return data

    def close(self):
        if self.closed_gently is not None:
            return
        self.closed_gently = False
        try:
            self.sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        deadline = time.time() + self.timeout
        try:
            while True:
                left = deadline - time.time()
                if left <= 0:
                    break
                self.sock.settimeout(left)
                if not self.sock.recv(IO_CHUNK):
                    self.closed_gently = True
                    break
        except TimeoutError:
            # Still there and saying nothing. We have waited the time we
            # said we would.
            pass
        except OSError:
            # Gone, which is the thing we were waiting for.
            self.closed_gently = True
        try:
            self.sock.close()
        except OSError:
            pass

    def __getattr__(self, name):
        return getattr(self.sock, name)


def serve_session(sock, allowed_keys, user=None, command=None,
    host_key=None, deadline=None, x_logger=None, job_uuid=None,
    private_key=None):
    """ One SSH session on an already connected socket.

    The socket is somebody else's business: a broker hands us one, and
    what travels through it is SSH, so the broker carries the session
    without being able to read it.

    <allowed_keys> are the keys that get in, as the bytes that go over
    the wire. Which keys those are is decided by the caller: normally
    this host's own authorized_keys for <user>, so a session as
    somebody is had with the key that lets that somebody in anyway, and
    where a job named a key of its own, that one key.

    With <job_uuid> and <private_key> the session begins with a line
    that vouches for its SSH host key, so the client can tell that it
    is talking to the host the job was for and not to whoever the
    broker put at the other end. Without them the session starts
    straight into SSH, which is what the tests of everything else here
    do.

    <deadline> is when the session has to be over. Nothing passes one in
    the daemon -- a shell lasts as long as it is used -- and the tests
    use it to get a session that ends by itself.

    Returns what the shell exited with and what ended the session, as
    (exit status, what ended it). The exit status is None where there was
    none to wait for, which is every ending but the shell's own.
    """
    x_logger = x_logger or logger
    if user is None:
        user = "root"
    # Asked before anything is spoken: a session for a user this host
    # does not have is over before it starts.
    user_entry = get_user_entry(user)
    if host_key is None:
        host_key = generate_host_key()
    if job_uuid and private_key:
        # Before the SSH banner: whoever is at the other end has to be
        # able to check who we are before it accepts our key.
        sock.sendall(build_host_vouch(job_uuid, host_key, private_key))
    server = RemoteAccessServer(allowed_keys=allowed_keys,
                                user=user,
                                command=command,
                                x_logger=x_logger)
    # So that a connection that is torn away says so instead of reading
    # like one that was finished with, which is the difference between
    # knowing why a session ended and guessing.
    rendezvous.tell_a_break_from_an_end(sock)
    # SSH gets a socket that closes without losing anything, because SSH
    # decides when it is closed and it does that in more ways than one.
    # It also watches for the moment SSH is told there is nothing more to
    # read, and asks the kernel what it makes of the connection then.
    session_socket = GentlyClosed(sock)
    transport = paramiko.Transport(session_socket)
    transport.banner_timeout = BANNER_TIMEOUT
    transport.handshake_timeout = HANDSHAKE_TIMEOUT
    transport.auth_timeout = AUTH_TIMEOUT
    transport.add_server_key(host_key)
    # So a client that is gone without saying so is noticed. Asked over
    # SSH and not over the connection, because the connection ends at
    # the broker and the question is about the client.
    transport.set_keepalive(KEEPALIVE_INTERVAL)
    pid = None
    master_fd = None
    # The terminal of the shell and its pid, once there is one. Kept out
    # here so the end of the session is written wherever it ends, see
    # below -- and the pid of its own, because the one above is given up
    # as soon as the shell has been waited for.
    terminal = None
    shell_pid = None
    # So that what SSH has to say about this session is in the log of
    # this session, and in its result, for as long as it lasts. Its
    # logger is let down to where a complaint gets through, since
    # whatever the rest of the process set it to was not set with this
    # in mind.
    ssh_log = logging.getLogger("paramiko")
    ssh_relay = SSHLogRelay(x_logger)
    ssh_log.addHandler(ssh_relay)
    ssh_log_level = ssh_log.level
    if ssh_log.getEffectiveLevel() > logging.WARNING:
        ssh_log.setLevel(logging.WARNING)
    try:
        transport.start_server(server=server)
        channel = transport.accept(AUTH_TIMEOUT)
        if channel is None:
            if server.auth_key is None:
                # Told apart from a client that got in and then asked
                # for nothing: a client offers the keys it has, and
                # none of them being one of ours is the one thing
                # whoever asked for the shell can do something about.
                msg = _("None of the keys offered is allowed here.")
                raise OTPmeException(msg)
            msg = _("No session was asked for.")
            raise OTPmeException(msg)
        if job_uuid and private_key:
            # Before the shell and not with the vouch: this is the one
            # thing a host can only say once the key exchange is done,
            # because that is where the id of the session comes from.
            # Sent as soon as there is a channel to send it on, so the
            # client has it before it asks for anything.
            channel.sendall(build_session_bind(job_uuid,
                                        transport.session_id,
                                        private_key))
        if not server.shell_event.wait(SHELL_TIMEOUT):
            msg = _("No shell was asked for.")
            raise OTPmeException(msg)
        log_msg = _("Remote access session opened for user {user} with key: {fingerprint}", log=True)[1]
        log_msg = log_msg.format(user=user,
                            fingerprint=server.auth_key.get_fingerprint().hex())
        x_logger.info(log_msg)
        pid, master_fd = start_shell(server, user_entry)
        server.master_fd = master_fd
        set_window_size(master_fd, server.columns, server.rows)
        # A shell on this host is a login on this host, so it goes where
        # the other logins are. What "last" shows as the origin is the
        # job: whoever asked for the shell, which host the key belongs
        # to and when it was signed are all on it
        # ("otpme-deploy show <uuid>"), and the uuid is the one thing
        # that leads to all of it.
        terminal = wtmp.terminal_name(master_fd)
        shell_pid = pid
        origin = "otpme-shell"
        if job_uuid:
            origin = f"otpme/{str(job_uuid)[:8]}"
        # The pid of the shell, the way sshd and login(1) put it in:
        # "last" asks whether that process is still alive to tell a
        # session that is running from one whose end was never written.
        # The pid of whoever writes the record says nothing about that.
        wtmp.login(terminal, user_entry.pw_name, origin, pid=pid)
        ended_by = pump(channel, master_fd, deadline=deadline)
        if ended_by.startswith("lost"):
            # What SSH made of it, where it made anything of it. Without
            # this the result says the write failed, which is the thing
            # that was already obvious -- the socket was closed, and why
            # it was closed is what the transport keeps.
            ended_by = f"{ended_by}{why_ssh_gave_up(transport)}"
            # And what the kernel made of the connection at the moment
            # SSH was told there was nothing more on it. A connection the
            # kernel still calls established is one that nobody ended,
            # whatever SSH was told -- and telling those two apart is
            # what every hour of finding this cost. It stays.
            if session_socket.quiet_because:
                ended_by = f"{ended_by}; {session_socket.quiet_because}"
        exit_status = None
        if ended_by == "shell":
            exit_status = os.waitpid(pid, 0)[1]
            pid = None
            exit_status = os.waitstatus_to_exitcode(exit_status)
            try:
                channel.send_exit_status(exit_status)
            except Exception:
                pass
        # Before the connection goes, and not by going: the client is
        # waiting to be told that there is nothing more.
        end_channel(channel)
        log_msg = _("Remote access session closed ({ended_by}).", log=True)[1]
        log_msg = log_msg.format(ended_by=ended_by)
        x_logger.info(log_msg)
        return exit_status, ended_by
    finally:
        if terminal is not None:
            # Here and not beside the login above: a session ends in
            # more ways than one, and one that is not written as ended
            # stands in "last" as still logged in for good.
            wtmp.logout(terminal, shell_pid)
        if pid is not None:
            # The client left or the time ran out, and the shell is
            # still there. It goes, with its whole process group: what
            # it started belongs to the session.
            try:
                os.killpg(os.getpgid(pid), signal.SIGHUP)
            except OSError:
                pass
            try:
                os.waitpid(pid, 0)
            except OSError:
                pass
        if master_fd is not None:
            try:
                os.close(master_fd)
            except OSError:
                pass
        # This closes the socket, which is a GentlyClosed one: what a
        # shell put out last is still on its way, and an ordinary close
        # would throw it away.
        try:
            transport.close()
        except Exception:
            pass
        ssh_log.removeHandler(ssh_relay)
        ssh_log.setLevel(ssh_log_level)
