# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
""" Asking a host for a shell, and taking it.

What otpme-shell does, in the order it does it:

    take the keys the SSH agent holds
    have a remote_access job made for the host
    meet the host at the broker, under the uuid of that job
    read what the host says about its SSH host key, and check it
    speak SSH, offering those keys until the host takes one

The keys are the agent's, and the host holds them against its own
authorized_keys for the user the shell runs as -- the ones sshd is
handed by otpme-get-authorized-keys. So a session as somebody is had
with the key that lets that somebody in anyway, nothing has to be put
in place for it, and a key taken away from a user is taken away here
with it.

With --throwaway-key none of that is used: a key pair is made for the
session, the job carries its public half, and the host lets in that one
key and nothing else -- a shell on a key that existed for five minutes
and was never in a file.

That one needs only the signature of the job, where the ordinary way
needs the signature and a key the host already holds. So the host says
who may ask for it, per signer: add_signer --allow-throwaway-key.

The host is checked before a word of SSH is spoken. The broker brings
two parties together and nothing stops it from bringing the wrong ones,
so the host vouches for its SSH host key with the key it was joined
with, and that is held against what the tree says about the host we
asked for.
"""
import contextlib
import io
import os
import socket
import sys
import threading

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import config
from otpme.lib import rendezvous

from otpme.lib.exceptions import *

logger = config.logger

# How long a shell job lives. Short on purpose: it is used right away
# or not at all, and the host refuses a longer one anyway. It says until
# when a shell may be asked for and not how long one may be used: a
# session lasts as long as somebody is working in it.
DEFAULT_SHELL_TTL = "5m"
# How often we ask the host whether it is still there, so a session
# whose far end is gone does not sit here looking open.
KEEPALIVE_INTERVAL = 30
# How a session ended, which is what the user is told afterwards.
ENDED_CLOSED = "closed"
ENDED_LOST = "lost"
# What we exit with where it was the connection that failed and not the
# command. The same as ssh, so a script around this reads the two apart
# the way it already does for ssh.
CONNECTION_FAILED = 255
# And what we exit with where whoever asked for the shell gave up on it.
# 128 plus the signal, which is what a shell reports for a command that
# was interrupted, so it reads as what it is.
ABORTED = 130
# What we ask the host to put in the environment of the shell: our own
# language, so a terminal at the other end shows what is typed into it.
# Nothing else -- the host takes nothing else either, and a shell that
# runs with the environment of whoever asked for it is a shell that runs
# their code.
SEND_ENV = ["LANG", "LC_ALL", "LC_CTYPE", "LC_COLLATE", "LC_TIME",
            "LC_NUMERIC", "LC_MONETARY", "LC_MESSAGES"]


def take_job_back(job_uuid, cancel):
    """ Take back a job nobody is going to use.

    Whoever gives up on a shell -- Ctrl+C, or a wait that ran out --
    leaves a job that asks a host for one. A host that has not picked
    it up yet would still do so, and open a session nobody is at the
    other end of. One that has picked it up is not stopped by this, but
    the job then says that nobody wanted it any more.

    <cancel> sends "otpme-deploy cancel <uuid>" and is handed in by
    whoever has a connection to mgmtd, which is what keeps this module
    free of daemons.

    Held interruptible, and said before it starts. Taking a job back
    goes to mgmtd and waits for the answer, while the signal handler in
    place is the one of that connection -- and that one swallows Ctrl+C
    on purpose, because it is there to stop a job on the server and is
    the last word (protocols/otpme_client.py). So whoever had just
    given up on waiting pressed Ctrl+C again and nothing happened at
    all. The handler that raises goes back in on top of it for as long
    as this takes, and the line says what is going on meanwhile.

    Says what came of it either way. A job that still stands is
    something the user has to know about, and then the command to take
    it back by hand is all that is left to offer.
    """
    from otpme.lib.messages import error_message

    def say_what_is_left():
        msg = _("The request stands until it expires: otpme-deploy cancel {job_uuid}")
        msg = msg.format(job_uuid=job_uuid)
        error_message(msg)

    msg = _("Taking the request back...")
    error_message(msg)
    try:
        with interruptible():
            cancel()
    except KeyboardInterrupt:
        msg = _("Gave up on taking the request back.")
        error_message(msg)
        say_what_is_left()
        return False
    except Exception as e:
        msg = _("Unable to take the request back: {error}")
        msg = msg.format(error=e)
        error_message(msg)
        say_what_is_left()
        return False
    msg = _("The request was taken back.")
    error_message(msg)
    return True


@contextlib.contextmanager
def interruptible():
    """ Ctrl+C gets somebody out again while this is held.

    An interactive OTPme connection puts a SIGINT handler of its own in
    (protocols/otpme_client.py), and the one for mgmtd neither raises
    nor passes the signal on: it is there to stop a job on the server,
    and it is the last word. Nobody puts the old handler back when the
    connection is done with, so it stays in for the rest of the
    process.

    For every other command that is the end of the command anyway. Not
    for this one: the job of a shell is made over mgmtd, and the waiting
    starts afterwards. So Ctrl+C did nothing from the moment the job was
    signed for, and whoever asked for a shell from a host that does not
    answer sat out the two minutes the broker waits for it.

    Held only where the waiting is and where the terminal is still the
    terminal. Once the session is up, Ctrl+C belongs to the shell at the
    other end and is a byte like any other (run_channel sets the
    terminal raw, which is what takes the signal out of it).
    """
    import signal
    def give_up(_signal, _frame):
        raise KeyboardInterrupt

    try:
        before = signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGINT, give_up)
    except (ValueError, OSError):
        # Not the main thread, where this is nobody's to change. Then
        # it stays as it is: a shell that cannot be interrupted is
        # better than one that cannot be had.
        yield
        return
    try:
        yield
    finally:
        try:
            signal.signal(signal.SIGINT, before)
        except (ValueError, OSError):
            pass


def get_agent_keys():
    """ The keys the SSH agent holds, in the order it offers them.

    What ssh itself would use. Nothing is generated and nothing is read
    from disk, so a key that lives on a smartcard or in a hardware
    token works here the way it works everywhere else: the agent signs
    and the private half never comes near this process.

    Asked where the keys are about to be used, and not a moment
    earlier. Each of them signs through the connection to the agent
    that this opens, and such a connection does not keep: measured on a
    forwarded agent, a connection that was idle for thirty seconds was
    gone, with "lost ssh-agent" on the next word to it. Asking at the
    start of otpme-shell and signing after the job had been made and
    signed for was well past that -- see check_agent(), which is what
    runs before the job is made and holds on to nothing.

    The order is the agent's, which is the order ssh offers them in,
    and it is not an arbitrary one: an agent that keeps a card lists
    the key of the card that is plugged in first. So the first key
    offered is the one that can be used, and the keys of the cards in
    somebody's drawer are never reached.

    The same key twice is one key. An agent holds one twice easily
    enough -- the card that is in, and the same key again from its own
    list -- and offering it twice gets the same answer twice.
    """
    import paramiko
    keys = []
    seen = []
    for key in paramiko.Agent().get_keys():
        blob = key.asbytes()
        if blob in seen:
            continue
        seen.append(blob)
        keys.append(key)
    if not keys:
        if not os.environ.get("SSH_AUTH_SOCK"):
            msg = _("No SSH agent here: SSH_AUTH_SOCK is not set.")
            raise OTPmeException(msg)
        msg = _("The SSH agent holds no key.")
        raise OTPmeException(msg)
    return keys


def check_agent():
    """ That there is an agent with a key in it, and nothing else.

    Run before the job is made, because a job that is made and then
    not used is a shell nobody takes, lying around for the minutes it
    lives.

    What it finds out is thrown away on purpose. The keys are asked for
    again where they are signed with, because the connection they would
    sign through does not survive the minutes in between -- see
    get_agent_keys().
    """
    get_agent_keys()


def generate_throwaway_key():
    """ The key pair of one session, thrown away after it.

    Not what otpme-shell does by default -- that uses the keys of the
    agent, which are the keys the host lets in anyway. This is for a
    shell on a key that exists for the minutes the job lives and is in
    no file: the job carries its public half, and then the host lets in
    that key and nothing else.

    It is also the way in that needs nothing but the signature of the
    job, so the host only takes it from a signer that was given the
    permission by hand -- see confd/job.py check_throwaway_key().

    Ed25519 because it is small and every SSH implementation of this
    decade knows it. Never written anywhere: it exists for the minutes
    the job lives, and a key that is not stored cannot be stolen from
    where it was stored.
    """
    import paramiko
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    private_key = ed25519.Ed25519PrivateKey.generate()
    openssh = private_key.private_bytes(serialization.Encoding.PEM,
                                    serialization.PrivateFormat.OpenSSH,
                                    serialization.NoEncryption())
    key = paramiko.Ed25519Key.from_private_key(io.StringIO(openssh.decode()))
    public_key = f"{key.get_name()} {key.get_base64()} otpme-shell"
    return key, public_key


def build_job_command(host, public_key=None, user=None,
    command=None, job_ttl=None):
    """ The command line that asks for the job.

    Built here rather than spoken to the nodes directly, so the job is
    made the way every other job is made -- signed, and checked against
    allow_confd_jobs on the way.

    <public_key> only where the session has a key of its own. Without
    one the job names no key, and the host lets in what its own
    authorized_keys for <user> lets in.
    """
    command_line = [
                "add",
                "--host", host,
                "--expiry", job_ttl or DEFAULT_SHELL_TTL,
                "--on-demand",
                "--return-uuid",
                ]
    if public_key:
        command_line += ["--arg", f"pubkey={public_key}"]
    if user:
        command_line += ["--arg", f"user={user}"]
    if command:
        command_line += ["--arg", f"command={command}"]
    command_line += ["remote_access", "shell"]
    return command_line


def read_host_public_key(host_uuid):
    """ The key a host was joined with, out of our own copy of the realm.

    Never asked of a management daemon over the network. The answer
    decides which host a session may be with, and a daemon that answers
    it decides that -- the whole of the vouch is that the client works
    it out for itself. A node reads the object, a host asks hostd for
    it, the same two ways stuff.resolve_oid() goes.
    """
    from otpme.lib import backend
    from otpme.lib import connections
    if config.use_backend:
        for object_type in ["host", "node"]:
            x_host = backend.get_object(object_type=object_type,
                                    uuid=host_uuid)
            if x_host:
                return x_host.public_key
        return None
    try:
        hostd_conn = connections.get("hostd")
    except Exception as e:
        msg = _("Error connecting to hostd: {e}")
        msg = msg.format(e=e)
        raise OTPmeException(msg) from e
    return hostd_conn.get_host_public_key(host_uuid)


def get_host_public_key(host):
    """ The key we check the host against.

    What our own copy of the realm says, and with PIN_HOST_KEYS what we
    have written down about this host instead -- see host_key_pins.py.
    Whoever can change the realm can change the key a session is held
    against, and a pin is what stops that: the key we hold the host to
    is the key that counts, and a different one waits for somebody with
    root to say yes to it.
    """
    host_uuid = get_host_uuid(host)
    public_key = read_host_public_key(host_uuid)
    if not config.pin_host_keys:
        if public_key:
            return public_key
        msg = _("Host has no public key: {host}")
        msg = msg.format(host=host)
        raise OTPmeException(msg)

    from otpme.lib import host_key_pins
    pinned = host_key_pins.get_pin(host_uuid)
    if not pinned:
        # Written down by the sync that brings a host, so there is one
        # for every host this one knows about. None means the host was
        # never synced here, or somebody took the pin away.
        msg = _("No key written down for this host: {host}")
        msg = msg.format(host=host)
        raise OTPmeException(msg)
    if public_key and public_key.strip() != pinned:
        # What is written down wins, and the session is not opened: a
        # key that changed is either a host that was rejoined or
        # somebody who changed the realm, and the two look the same
        # from here.
        msg = _("The key of this host changed: {host}")
        msg = msg.format(host=host)
        raise OTPmeException(msg)
    return pinned


def get_host_uuid(host):
    """ The uuid of the host a job is for, which is how a key is filed.

    By uuid and not by name, the same way a signer key is filed: a host
    that is renamed is the same host, and a name given to another host
    is not the same host.

    Resolved and not searched for. A host runs its tools against hostd
    and not against the tree -- no object type is registered there and
    the index cannot be searched (lib/__init__.py, do_hostd_init) -- and
    stuff.resolve_oid() asks hostd where there is no backend. What it
    needs is an OID, and the read OID of a host is realm, site and name
    with no unit in it (classes/host.py, register_oid), which is all we
    have here.

    Our own realm and site, because that is the host a job can be made
    for.
    """
    from otpme.lib import oid
    from otpme.lib import stuff
    from otpme.lib.register import register_module
    # For the OID schema of the two types. Nothing of the tree is read
    # by this, and it needs neither the backend nor the master key, so
    # a shell is still not root's.
    register_module("otpme.lib.classes.host")
    register_module("otpme.lib.classes.node")
    for object_type in ["host", "node"]:
        object_id = oid.get(object_id=(f"{object_type}|{config.realm}"
                                    f"/{config.site}/{host}"))
        try:
            return stuff.resolve_oid(object_id)
        except UnknownOID:
            continue
    msg = _("Unknown host: {host}")
    msg = msg.format(host=host)
    raise OTPmeException(msg)


class WatchedSocket(rendezvous.WaitedFor):
    """ The socket of a session, with a note of why it went quiet.

    Waited for before it is called, which is what the base class is for:
    SSH reads the connection in a thread of its own while the session
    writes to it, and a call that has to come back round for more while
    the other thread is inside takes the connection apart.

    Everything goes through to the socket underneath. What is kept is
    what the kernel made of the connection the first time a read came
    back with nothing, or with an error.

    That is a question that cannot be answered afterwards. A read of
    nothing on a connection the kernel still calls established is not an
    end at all, only a call that came apart; on one the kernel calls
    close-wait the far end really did hang up. Later on the two look the
    same, because by then the connection is gone either way.
    """
    TCP_STATES = {
                1:"established", 2:"syn-sent", 3:"syn-received",
                4:"fin-wait-1", 5:"fin-wait-2", 6:"time-wait",
                7:"closed", 8:"close-wait", 9:"last-ack", 10:"listening",
                11:"closing",
                }

    def __init__(self, sock):
        super().__init__(sock)
        self.read = 0
        self.quiet_because = None

    def state(self):
        """ What the kernel calls this connection, in a word. """
        try:
            info = self.sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 1)
            return self.TCP_STATES.get(info[0], f"state {info[0]}")
        except (OSError, AttributeError, IndexError):
            return "cannot be asked"

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
            if self.quiet_because is None:
                self.quiet_because = (f"{self.why(e)} after {self.read} "
                                f"bytes, in thread "
                                f"{threading.current_thread().name}, "
                                f"the kernel calls it {self.state()}")
            raise
        if not data and self.quiet_because is None:
            self.quiet_because = (f"a read of nothing after {self.read} "
                                f"bytes, in thread "
                                f"{threading.current_thread().name}, "
                                f"the kernel calls it {self.state()}")
        self.read += len(data)
        return data

    def __getattr__(self, name):
        return getattr(self.sock, name)


def connect_to_host(job_uuid, host_public_key):
    """ Meet the host at the broker and check that it is the host.

    The broker is the master node of the site, reached over its
    management address: racd runs where the master role is, because the
    address both sides are told to meet at is the floating IP, and that
    goes with the role.

    Returns a socket that is at the beginning of an SSH handshake with
    the host the job was for, or raises.
    """
    from otpme.lib import connections
    from otpme.lib.confd import remote_access
    from otpme.lib import rendezvous
    rac_conn = connections.get("racd")
    sock = rac_conn.meet(key=job_uuid, role="client")
    # So that a connection that is torn away says so instead of reading
    # like one that was finished with. Both of them arrive as nothing at
    # all otherwise, and then neither end of a session that broke can say
    # anything but that the other one hung up.
    rendezvous.tell_a_break_from_an_end(sock)
    # Before a word of SSH: whoever is at the other end has to say who
    # it is, and the broker is not asked about it.
    vouch = remote_access.read_host_vouch(sock)
    host_key_blob = remote_access.verify_host_vouch(vouch, job_uuid,
                                                host_public_key)
    # Watched from here on, because a session that ends by itself leaves
    # nothing behind that says which end did it.
    return WatchedSocket(sock), host_key_blob


def offer_keys(transport, session_keys):
    """ Offer the keys we have until the host takes one.

    The way ssh does it, and for the same reason: which of our keys the
    host lets in is the host's to say, and the agent usually holds more
    than one. A key the host refuses is not an error -- it is the next
    key's turn -- and only having none left is.

    Returns the key that got in.
    """
    import paramiko
    refused = []
    for session_key in session_keys:
        fingerprint = session_key.get_fingerprint().hex()
        try:
            # The user name is not looked at by the host -- which user
            # the shell runs as is in the signed job -- but SSH wants
            # one.
            transport.auth_publickey("otpme", session_key)
        except paramiko.AuthenticationException:
            refused.append(f"{fingerprint} is not allowed there")
        except paramiko.SSHException as e:
            refused.append(f"{fingerprint} could not be used: {e}")
        else:
            if transport.is_authenticated():
                return session_key
            refused.append(f"{fingerprint} got us nowhere")
        if not transport.is_active():
            # A key that signed a moment ago and not now -- a card
            # pulled in between -- still takes the session with it, and
            # then there is nothing left to offer the rest to.
            break
    msg = _("No key of ours got us in: {refused}")
    msg = msg.format(refused="; ".join(refused) or "there were none to offer")
    raise OTPmeException(msg)


def run_session(sock, host_key_blob, session_keys=None, command=None,
    host_public_key=None, job_uuid=None):
    """ The SSH session itself, on a socket that is already there.

    <session_keys> are the keys to offer, in the order to offer them.
    None means the keys of the SSH agent, taken here rather than handed
    in: each of them signs through a connection to the agent, and that
    connection does not survive the making of the job (get_agent_keys).

    With <host_public_key> and <job_uuid> the host has to show, once the
    session stands, that it is the end of it and not a party carrying it
    -- see remote_access.build_session_bind(). Without them the session
    is taken as it is, which is what the tests of everything else here
    do.

    Returns what ran at the other end exited with, how the session
    ended, and what was said about it where it did not end cleanly.
    """
    import paramiko
    # Everything up to the session itself can wait on a host that says
    # nothing, so Ctrl+C has to get somebody out of it. Not the session:
    # there Ctrl+C is the shell's.
    with interruptible():
        transport = paramiko.Transport(sock)
        transport.start_client(timeout=30)
        # So a host that is gone without saying so is noticed. Asked over
        # SSH, because the connection ends at the broker and the question
        # is about the host.
        transport.set_keepalive(KEEPALIVE_INTERVAL)
        # The key the host vouched for, and no other. Checked here and
        # not left to a policy: the whole point of the vouch is that this
        # is decided before anything is said.
        server_key = transport.get_remote_server_key()
        if server_key.asbytes() != host_key_blob:
            transport.close()
            msg = _("The host is not using the key it vouched for.")
            raise OTPmeException(msg)
        try:
            if session_keys is None:
                session_keys = get_agent_keys()
            offer_keys(transport, session_keys)
        except (OTPmeException, KeyboardInterrupt):
            transport.close()
            raise
        channel = transport.open_session()
        if host_public_key and job_uuid:
            # The vouch said which SSH key this session would be with.
            # It did not say that the key belongs to the host that
            # vouched for it -- a host may name any key, including a
            # third one's, and splice us through to that third host.
            # Then everything above holds and we are working on a
            # machine we never asked for.
            #
            # So the host has to sign the id of this session, which
            # only an end of the key exchange can know. Against our own
            # id, never one off the wire.
            from otpme.lib.confd import remote_access
            try:
                line = remote_access.read_session_bind(channel)
                remote_access.verify_session_bind(line, job_uuid,
                                        transport.session_id,
                                        host_public_key)
            except (OTPmeException, KeyboardInterrupt):
                transport.close()
                raise
    try:
        return run_channel(channel, command=command)
    finally:
        try:
            transport.close()
        except Exception:
            pass


def send_environment(channel):
    """ Ask the host for our language in the shell.

    Only what we have: a variable we do not have is not sent as an empty
    one, because an empty LANG is a locale of its own and not the absence
    of one. A host that refuses says so silently, the way every SSH
    server does, so nothing here waits for an answer.
    """
    for name in SEND_ENV:
        value = os.environ.get(name)
        if not value:
            continue
        try:
            channel.set_environment_variable(name, value)
        except Exception:
            # Not worth ending a session over: a shell without our
            # language still works, it just shows less.
            pass


def run_channel(channel, command=None):
    """ Put our terminal at the other end of the channel.

    Returns (exit status, how it ended, what was said about it). The
    exit status is None where the other end did not say one, which is
    what happens when a session is lost rather than closed.
    """
    import tty
    import termios
    import select
    interactive = sys.stdin.isatty()
    if interactive:
        size = os.get_terminal_size()
        channel.get_pty(term=os.environ.get("TERM", "xterm"),
                    width=size.columns,
                    height=size.lines)
    # Before the shell is asked for, because the environment of a shell
    # is settled when it starts. A host that does not want it says no and
    # the session goes on without it.
    send_environment(channel)
    if command:
        channel.exec_command(command)
    else:
        channel.invoke_shell()
    old_mode = None
    if interactive:
        old_mode = termios.tcgetattr(sys.stdin)
        # Raw, so what the user types reaches the shell at the other
        # end instead of being line edited here.
        tty.setraw(sys.stdin.fileno())
    def ended_cleanly():
        """ Whether the far end said the session was over.

        There is nothing in "no more data" that says which it was: a
        channel gives nothing both when the host has closed it and when
        the connection under it is gone. What tells them apart is the
        far end having said so -- an EOF, which only the far end sends --
        or, where it never got that far, the connection still being
        there.
        """
        if channel.eof_received:
            return True
        return channel.get_transport().is_active()

    def why_it_went():
        """ What SSH made of it, where it made anything of it.

        A transport that dies keeps the reason, and without asking for it
        a session that broke is reported as having broken and nothing
        else -- which is the one thing that was already obvious.

        Whether the connection was torn away or simply ended is in that
        reason, because the socket was asked to tell them apart rather
        than report both as nothing (see connect_to_host).
        """
        try:
            error = channel.get_transport().get_exception()
        except Exception:
            return None
        if not error:
            return None
        return str(error) or type(error).__name__

    ended_by = ENDED_CLOSED
    reason = None
    try:
        while True:
            readable = select.select([channel, sys.stdin], [], [], 1.0)[0]
            if channel in readable:
                if channel.recv_ready():
                    data = channel.recv(65536)
                    if not data:
                        if not ended_cleanly():
                            ended_by = ENDED_LOST
                        break
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()
                elif channel.exit_status_ready() or channel.closed:
                    if not ended_cleanly():
                        ended_by = ENDED_LOST
                    break
            if sys.stdin in readable:
                data = sys.stdin.buffer.raw.read(65536)
                if not data:
                    channel.shutdown_write()
                    continue
                channel.sendall(data)
            if not ended_cleanly():
                # Nothing was said and the session is gone, so the host
                # or whatever carried it is no longer there.
                ended_by = ENDED_LOST
                break
    except Exception as e:
        # Whatever went wrong here, the session is over and the terminal
        # is still in raw mode. Said as one line afterwards rather than
        # as a traceback into a terminal that cannot even break lines.
        ended_by = ENDED_LOST
        reason = str(e) or type(e).__name__
    finally:
        if old_mode is not None:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_mode)
    if ended_by == ENDED_LOST and not reason:
        reason = why_it_went()
    exit_status = None
    if channel.exit_status_ready():
        exit_status = channel.recv_exit_status()
    return exit_status, ended_by, reason
