# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
""" Bringing two parties together and getting out of the way.

A remote access job names a host and a key. The host connects out to a
broker and so does whoever asked for the shell; both say which job they
are here for, and from then on the broker moves bytes between them and
reads none of them. What travels is SSH, between the client and the
host, so the broker carries the session without being able to listen to
it or to speak into it.

Nothing in here knows what SSH is. It knows two parties, one key, and a
socket each.

The key is the uuid of the job. Both sides have it already -- one made
the job, the other was sent it -- so nothing has to be handed from one
to the other first. It is not a secret and it does not need to be: the
host only shows up for a job it verified, and whoever cannot answer the
host's SSH authentication gets nothing but a closed connection out of
the meeting.

One meeting per key. Once two parties have met, the key is spent, so a
third party arriving later meets nobody, however fast it was.
"""
import os
import ssl
import time
import select
import socket
import threading

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import config

from otpme.lib.exceptions import *

logger = config.logger

# The two sides of a meeting. They are named so that two hosts or two
# clients cannot be spliced to each other.
ROLE_HOST = "host"
ROLE_CLIENT = "client"
ROLES = [ROLE_HOST, ROLE_CLIENT]

# How long the first party waits for the second. Only for the second
# party turning up: once it has, the session lasts as long as it lasts.
WAIT_TIMEOUT = 120
# How long a session may last once the two have met. None, because there
# is no length at which a shell somebody is working in becomes wrong.
# What a limit here would really be aimed at is a session whose far end
# is gone without saying so, and that is what the keepalive below is
# for: a dead session ends in minutes and a live one is left alone.
SESSION_TIMEOUT = None
# How much longer the party that only watches waits for the end of a
# session than the one that carries it.
SESSION_END_GRACE = 60
# How a dead far end is noticed. Without this a session whose far end
# is gone sits here until TCP gives up on its own, which can be hours,
# and all that time it holds a connection, a thread and a blocker
# against the master failover.
KEEPALIVE_IDLE = 60
KEEPALIVE_INTERVAL = 15
KEEPALIVE_COUNT = 4
# How much may travel through one session. None, for the same reason
# there is no limit on how long one may last: there is no amount at
# which a shell somebody is working in becomes wrong. A listing of a
# whole filesystem is gigabytes and is nobody's idea of a file transfer,
# and whoever did want to move data through a shell can do that anyway --
# the shell is the channel. So this stopped the work and not the misuse.
# A caller that wants a limit still passes one; the tests do.
MAX_SESSION_BYTES = None
# The largest chunk moved in one go. Never below 16 KiB, which is the
# largest a TLS record gets: a TLS socket reads a whole record and then
# hands it out in pieces, so a read of less than a record leaves the rest
# inside the socket, where select() cannot see it -- the kernel has
# nothing left, so select() says there is nothing to do. Reading a whole
# record never leaves that behind. It is no protection against anything
# else: several records arriving together are still several reads, and
# what has not been read yet waits in the kernel, where select() does see
# it.
IO_CHUNK = 65536
# How many meetings may be waiting at once. Every one of them holds a
# connection and a thread.
MAX_WAITING = 256
# How long a spent key is remembered, so the second meeting under it is
# refused and not simply the beginning of a new one.
SPENT_KEY_MEMORY = 3600


def set_keepalive(sock):
    """ Have the kernel notice a far end that is gone.

    Quietly does nothing where the socket is not one that can do it: a
    session over a unix socket or a socket pair has both ends in reach
    anyway.
    """
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE,
                        KEEPALIVE_IDLE)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL,
                        KEEPALIVE_INTERVAL)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT,
                        KEEPALIVE_COUNT)
    except (OSError, AttributeError):
        pass


def no_more_from_us(sock):
    """ Say at the socket level that nothing else is coming from here.

    Whatever is already on its way out gets there first, which a close
    does not promise: a socket closed while something is still unread on
    the way in is closed with a reset, and a reset throws away whatever
    of ours the far end has not had yet. At the end of a busy session
    that is the tail of it -- the last of a shell's output, after the
    shell has already exited.

    Quietly does nothing for a socket that has no such thing.
    """
    try:
        sock.shutdown(socket.SHUT_WR)
    except (OSError, AttributeError):
        pass


def tell_a_break_from_an_end(sock):
    """ Have a torn-away connection say so instead of looking finished.

    A TLS socket answers a far end that was torn away with the same
    nothing it answers for one that said goodbye, because it is asked to:
    suppress_ragged_eofs is on by default. Both ends of a session then
    report that the other one hung up, and there is no way left to find
    out that neither did.

    Asking for it the other way round costs nothing: measured here, a
    reset raises and the orderly half close this module sends still reads
    as the nothing it is. Quietly does nothing for a socket that has no
    such thing to ask.
    """
    if hasattr(sock, "suppress_ragged_eofs"):
        try:
            sock.suppress_ragged_eofs = False
        except AttributeError:
            pass


class WaitedFor(object):
    """ A socket that is waited for before it is called.

    An OpenSSL connection is one object with one state machine, and SSH
    puts two threads in it: its own thread reads the connection while
    whoever uses a channel writes to it. That is fine as long as neither
    call comes back round for more while the other one is inside.

    Which is what a timeout makes them do, and a timeout is what SSH puts
    on the socket it is given -- a tenth of a second, so that it can
    notice being asked to stop. With one, the ssl module works the socket
    without blocking: read, nothing there yet, wait, read again, all
    inside the one call the caller made. Those turns are what overlap,
    and what comes out of the overlap is a read of nothing at all on a
    connection the kernel still calls established -- which is what every
    lost session reported, at every size from fifteen megabytes to a
    thousand.

    Measured on four hundred megabytes through two threads on one socket:

        no timeout on the socket      it holds
        a tenth of a second, called   it breaks inside two megabytes
        a tenth of a second, waited   it holds
          for first

    So the socket is watched with select() first, and the call that
    follows then finishes in one go and has nothing to come back round
    for. Waiting is also all this does: a lock around the calls was tried
    and taken out again, because the measurement above is the same with
    and without one, and a guard that nothing can be shown to need is a
    guard in the way.
    """
    def __init__(self, sock):
        self.sock = sock

    def wait_for(self, reading):
        """ Wait for the socket to be worth calling, without the lock.

        False where it never became so within the time the socket allows.
        Anything the TLS layer has already taken out of the kernel counts
        as ready: select() cannot see that, and waiting for the kernel to
        say so again would wait for ever.
        """
        if reading:
            try:
                if self.sock.pending():
                    return True
            except (AttributeError, OSError):
                pass
        timeout = self.sock.gettimeout()
        try:
            readable, writable = select.select([self.sock] if reading else [],
                                            [] if reading else [self.sock],
                                            [], timeout)[:2]
        except (OSError, ValueError):
            # Gone. Let the call itself say so.
            return True
        return bool(readable or writable)

    def recv(self, *args, **kwargs):
        while True:
            if not self.wait_for(reading=True):
                raise TimeoutError("timed out")
            try:
                return self.sock.recv(*args, **kwargs)
            except ssl.SSLWantReadError:
                continue
            except ssl.SSLWantWriteError:
                # It wants the other direction first, which happens while
                # keys are being changed.
                self.wait_for(reading=False)

    def send(self, data, *args, **kwargs):
        while True:
            if not self.wait_for(reading=False):
                raise TimeoutError("timed out")
            try:
                return self.sock.send(data, *args, **kwargs)
            except ssl.SSLWantWriteError:
                continue
            except ssl.SSLWantReadError:
                self.wait_for(reading=True)

    def sendall(self, data, *args, **kwargs):
        """ All of it, because send() sends what it can. """
        left = memoryview(data)
        while left:
            left = left[self.send(left, *args, **kwargs):]

    def __getattr__(self, name):
        """ Everything else is the socket's own.

        Only what goes through the connection is waited for first;
        settimeout(), fileno(), close() and the rest are not calls into
        it.
        """
        return getattr(self.sock, name)


def splice(sock_a, sock_b, deadline=None, max_bytes=MAX_SESSION_BYTES,
    names=None, x_logger=None):
    """ Move bytes between two sockets until one of them ends.

    Returns how much went each way, as (a to b, b to a).

    <names> is what to call the two of them in the log, in that order.

    What ended it is written down, because afterwards nobody can tell:
    both ends are told there is no more coming, so both of them report
    the same end of file whichever of them brought the session down. The
    one line here is the only place that says which.
    """
    x_logger = x_logger or logger
    if not names:
        names = ("one side", "the other side")
    set_keepalive(sock_a)
    set_keepalive(sock_b)
    tell_a_break_from_an_end(sock_a)
    tell_a_break_from_an_end(sock_b)
    sent = {sock_a:0, sock_b:0}
    peer = {sock_a:sock_b, sock_b:sock_a}
    side = {sock_a:names[0], sock_b:names[1]}
    ended_by = "nothing"
    while True:
        timeout = 1.0
        if deadline is not None:
            left = deadline - time.time()
            if left <= 0:
                ended_by = "the time it was given"
                break
            timeout = min(timeout, left)
        try:
            readable = select.select([sock_a, sock_b], [], [], timeout)[0]
        except (OSError, ValueError) as e:
            ended_by = f"a socket that cannot be watched: {e}"
            break
        ended = False
        for x_sock in readable:
            try:
                data = x_sock.recv(IO_CHUNK)
            except OSError as e:
                ended_by = f"an error reading {side[x_sock]}: {e}"
                ended = True
                break
            if not data:
                ended_by = f"{side[x_sock]} having nothing more to say"
                ended = True
                break
            try:
                peer[x_sock].sendall(data)
            except OSError as e:
                ended_by = (f"an error writing to {side[peer[x_sock]]}: {e}")
                ended = True
                break
            sent[x_sock] += len(data)
            if max_bytes and sum(sent.values()) > max_bytes:
                ended_by = "more than this session was allowed to carry"
                ended = True
                break
        if ended:
            break
    # Both ends are told that nothing else is coming, so what is still on
    # its way out gets there, and so the side that is waiting for more
    # learns there is none instead of waiting for it. Without this a
    # session whose other half had ended left the far end sitting on a
    # connection nobody was carrying any more.
    no_more_from_us(sock_a)
    no_more_from_us(sock_b)
    log_msg = _("Session ended by {ended_by}.", log=True)[1]
    log_msg = log_msg.format(ended_by=ended_by)
    x_logger.info(log_msg)
    return sent[sock_a], sent[sock_b]


def meet(point, key, role, sock, go_ahead, blocked_by=None):
    """ One side of a session, from the request to the end of it.

    What a protocol handler does once it has a "meet" request: check
    what it says, tell the other end to go ahead, and carry the session.
    Here and not in the handler so it can be driven without a daemon
    under it.

    <go_ahead> is called once the request is good for something. After
    that nothing may be written to the connection any more: the far end
    is speaking its own protocol by then.

    <blocked_by> holds the master failover off while this side is here,
    and says who for. A session lives on the node that holds the
    floating IP, so a failover in the middle of one takes the shell
    with it -- and whoever was working in it is the last to hear about
    it. One blocker per connection, which is why the role is part of
    its id: the two sides of a session arrive separately and leave
    separately.

    Raises OTPmeException where the request itself was no good, and the
    caller may still answer. Raises ConnectionHijacked once the go
    ahead is out, and then the caller may not. Returns how much went
    each way where there was a session.
    """
    from otpme.lib import stuff
    if point is None:
        msg = _("No rendezvous point.")
        raise OTPmeException(msg)
    if not key:
        msg = _("Missing key.")
        raise OTPmeException(msg)
    # The key of a meeting is the uuid of the job both sides are here
    # for. Checked for its shape and nothing else: what it stands for
    # is the business of the host, which verified the job, and of the
    # authentication that follows between the two of them.
    if not stuff.is_uuid(key):
        msg = _("Invalid key.")
        raise OTPmeException(msg)
    if role not in ROLES:
        msg = _("Invalid role.")
        raise OTPmeException(msg)
    # The last thing said in the protocol of whoever called us. It has
    # to be out before the session starts, or the other side would
    # speak into a connection that is still framing.
    go_ahead()
    blocker_id = None
    if blocked_by is not None:
        blocker_id = add_failover_blocker(key, role, blocked_by)
    try:
        return point.join(key, role, sock)
    except Exception as e:
        msg = _("No session: {error}")
        msg = msg.format(error=e)
        raise ConnectionHijacked(msg) from e
    finally:
        if blocker_id is not None:
            from otpme.lib import multiprocessing
            multiprocessing.del_master_failover_blocker(blocker_id)


def add_failover_blocker(key, role, blocked_by):
    """ Hold the master failover off while one side is here.

    The id carries the role as well as the job: both sides of a session
    are here at once, and one of them leaving must not take the blocker
    of the other with it.
    """
    from otpme.lib import multiprocessing
    name = _("racd: remote access session for job {key} ({role})")
    name = name.format(key=key, role=role)
    blocker_id = f"rac:{key}:{role}"
    return multiprocessing.add_master_failover_blocker(name,
                                                blocker_id=blocker_id,
                                                auth_token=blocked_by)


class Meeting(object):
    """ One party waiting for the other.

    Two things are waited for here and they are not the same thing. The
    other party turning up is one, and the session being over is the
    other -- and between them lies the whole session. One event for each,
    because waiting for the second where the first was meant puts a
    limit of two minutes on a shell.
    """
    def __init__(self, key, role, sock):
        self.key = key
        self.role = role
        self.sock = sock
        self.met = threading.Event()
        self.over = threading.Event()
        self.traffic = None
        self.error = None


class RendezvousPoint(object):
    """ Where the two parties of a session find each other.

    Held by the broker, one for the whole daemon. Every method may be
    called from any thread.
    """
    def __init__(self, wait_timeout=WAIT_TIMEOUT,
        session_timeout=SESSION_TIMEOUT, max_waiting=MAX_WAITING,
        max_bytes=MAX_SESSION_BYTES, x_logger=None):
        self.lock = threading.Lock()
        self.waiting = {}
        self.spent = {}
        self.wait_timeout = wait_timeout
        self.session_timeout = session_timeout
        self.max_waiting = max_waiting
        self.max_bytes = max_bytes
        self.logger = x_logger or logger

    def forget_spent_keys(self):
        """ Keys nobody can turn up for any more. Call with the lock. """
        now = time.time()
        for x_key in list(self.spent):
            if (now - self.spent[x_key]) < SPENT_KEY_MEMORY:
                continue
            self.spent.pop(x_key, None)

    def waiting_count(self):
        with self.lock:
            return len(self.waiting)

    def session_timeout_with_grace(self):
        """ How long this side waits for a session to be over.

        The side that carries the session stops it at the session
        timeout, so this is only a backstop for the case where that side
        is stuck in a write that never completes. A little longer than
        the session may last, so the one that is supposed to end it is
        the one that does.
        """
        if not self.session_timeout:
            return None
        return self.session_timeout + SESSION_END_GRACE

    def join(self, key, role, sock, wait_timeout=None):
        """ Wait for the other party and carry the session.

        Returns when the session is over, with how much went each way
        as (sent by us, received by us). Raises where there was no
        session: nobody came, somebody was here already, or the key is
        spent.

        Both parties get their own socket back to close. Neither closes
        the socket of the other.
        """
        if role not in ROLES:
            msg = _("Unknown role: {role}")
            msg = msg.format(role=role)
            raise OTPmeException(msg)
        if not key:
            msg = _("A meeting needs a key.")
            raise OTPmeException(msg)
        if wait_timeout is None:
            wait_timeout = self.wait_timeout
        meeting = Meeting(key=key, role=role, sock=sock)
        peer = None
        with self.lock:
            self.forget_spent_keys()
            if key in self.spent:
                msg = _("This meeting has been held already.")
                raise OTPmeException(msg)
            waiting = self.waiting.get(key)
            if waiting is None:
                if len(self.waiting) >= self.max_waiting:
                    msg = _("Too many meetings are waiting.")
                    raise OTPmeException(msg)
                self.waiting[key] = meeting
            elif waiting.role == role:
                # Two hosts or two clients. One of them is not what it
                # says it is, and neither is spliced to the other.
                msg = _("Somebody is already waiting as: {role}")
                msg = msg.format(role=role)
                raise OTPmeException(msg)
            else:
                peer = self.waiting.pop(key)
                self.spent[key] = time.time()
        if peer is None:
            # We were first. The one that comes second does the work
            # and tells us when it is over.
            if not meeting.met.wait(wait_timeout):
                with self.lock:
                    if self.waiting.get(key) is meeting:
                        self.waiting.pop(key, None)
                msg = _("Nobody came to the meeting.")
                raise TimeoutReached(msg)
            # The other party is here and carrying the session, so from
            # now on what we are waiting for is the end of it. A session
            # may last as long as a session may last, and this side
            # giving up early would take it down: our caller would stop
            # speaking the session's protocol on a socket the session is
            # still using.
            if not meeting.over.wait(self.session_timeout_with_grace()):
                msg = _("The session did not end.")
                raise TimeoutReached(msg)
            if meeting.error is not None:
                raise meeting.error
            # The traffic is counted from the point of view of whoever
            # did the splicing, so ours is the other way round.
            return meeting.traffic[1], meeting.traffic[0]
        # We came second, so the session is ours to carry. Said before
        # anything else: the other side is waiting to hear that we are
        # here, and until it does it is still on its own clock.
        peer.met.set()
        log_msg = _("Rendezvous: {role} met its peer.", log=True)[1]
        log_msg = log_msg.format(role=role)
        self.logger.debug(log_msg)
        deadline = None
        if self.session_timeout:
            deadline = time.time() + self.session_timeout
        try:
            traffic = splice(sock, peer.sock,
                            deadline=deadline,
                            max_bytes=self.max_bytes,
                            names=(role, peer.role),
                            x_logger=self.logger)
            peer.traffic = traffic
            return traffic
        except Exception as e:
            peer.error = e
            raise
        finally:
            peer.over.set()
