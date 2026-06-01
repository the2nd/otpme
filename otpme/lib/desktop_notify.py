# -*- coding: utf-8 -*-

# Copyright (C) 2014 the2nd <the2nd@otpme.org>
"""Desktop notification helper for otpme-agent.

Wraps the freedesktop Notifications spec (org.freedesktop.Notifications)
via jeepney so notifications can be raised from inside the agent without
shelling out to notify-send. Delivery is best-effort: if the session bus
is unreachable or no notification daemon is running, the call returns
None and logs at debug level.
"""
import os
import pwd
import socket

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import config

from otpme.lib.exceptions import *


# freedesktop notification spec urgency hint values.
URGENCY_LEVELS = {
    "low"       : 0,
    "normal"    : 1,
    "critical"  : 2,
}


def _resolve_urgency(urgency):
    if isinstance(urgency, str):
        try:
            return URGENCY_LEVELS[urgency.lower()]
        except KeyError:
            msg = _("Invalid urgency: {urgency} (expected one of {valid})")
            msg = msg.format(urgency=urgency,
                             valid=", ".join(sorted(URGENCY_LEVELS)))
            raise OTPmeException(msg)
    return int(urgency)


def _resolve_uid(user):
    """ Map None / int / str username to a numeric UID. Raises KeyError
    for unknown usernames. """
    if user is None:
        return os.getuid()
    if isinstance(user, int):
        return user
    return pwd.getpwnam(user).pw_uid


def _extract_unix_path(address):
    """ Pull the unix socket path out of a DBus address string like
    'unix:path=/run/user/1000/bus,guid=…'. Returns None for non-unix
    transports. """
    for transport in address.split(";"):
        transport = transport.strip()
        if not transport.startswith("unix:"):
            continue
        for kv in transport[len("unix:"):].split(","):
            if kv.startswith("path="):
                return kv[len("path="):]
    return None


def _probe_unix_socket(path, timeout=0.5):
    """ Verify a responsive DBus daemon is listening on the given unix
    socket. We can't trust connect() alone: a stale socket file with an
    accepting-but-unresponsive (or crashed) daemon will make jeepney's
    SASL handshake block forever. So we send the first byte of the DBus
    AUTH protocol (NUL + 'AUTH\\r\\n') and require some reply within
    the timeout window. A live daemon answers with 'REJECTED ...';
    anything we get back proves it's processing. """
    if not path or not os.path.exists(path):
        return False
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(path)
        sock.sendall(b"\0AUTH\r\n")
        reply = sock.recv(64)
        return bool(reply)
    except (OSError, socket.timeout):
        return False
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _scan_proc_env(uid, var_name="DBUS_SESSION_BUS_ADDRESS"):
    """ Walk /proc for processes owned by uid and yield distinct values
    of the named env var. Used as last-resort discovery when neither
    the caller's env nor /run/user/{uid}/bus yields a live bus -- e.g.
    SDDM+classic-KDE that puts the socket in /tmp/dbus-XXX and writes
    a stale ~/.dbus/session-bus/ file. The spec-defined session-bus
    file is unreliable in practice (only --autolaunch invocations
    update it, cleanup is racy), so we go straight to live process
    environments. Requires the caller to be uid or root. """
    seen = set()
    try:
        entries = os.listdir("/proc")
    except OSError:
        return
    for entry in entries:
        if not entry.isdigit():
            continue
        proc_dir = f"/proc/{entry}"
        try:
            if os.stat(proc_dir).st_uid != uid:
                continue
        except OSError:
            continue
        try:
            with open(f"{proc_dir}/environ", "rb") as fh:
                env_data = fh.read()
        except OSError:
            continue
        for kv in env_data.split(b"\0"):
            if not kv:
                continue
            try:
                k, v = kv.decode("utf-8", errors="replace").split("=", 1)
            except ValueError:
                continue
            if k != var_name:
                continue
            if v in seen:
                continue
            seen.add(v)
            yield v


# Why we discover the session bus ourselves instead of just trusting
# $DBUS_SESSION_BUS_ADDRESS the way libnotify / notify-send do:
#
# The otpme-agent is started by the PAM module *before* the user's
# graphical session exists. That means at agent-launch the env is
# essentially empty -- whatever PAM had (root's), not the desktop
# session's. Later, when we want to raise a notification (share
# mounted etc.), we need to find a bus address that wasn't handed to us.
#
# libnotify/notify-send do nothing clever here: they read the env var,
# and if it's missing they fall back to $XDG_RUNTIME_DIR/bus or X11
# autolaunch. From outside the session they simply can't reach the
# user's bus. So we have to do more than they do, otherwise share-mount
# notifications would only ever work when the agent happens to inherit
# a session env (it doesn't).
#
# The DBus spec mentions ~/.dbus/session-bus/<machine-id>-<display> as
# a discovery file, but in practice it's unreliable: only --autolaunch
# invocations update it (KDE/SDDM typically use --exit-with-session
# which doesn't), and stale-file detection at session start is racy.
# So we skip it.
#
# What does work reliably is /proc/*/environ of the user's running
# processes -- whatever the live session uses, kwin/plasmashell/etc.
# carry it. /run/user/{uid}/bus catches systemd-managed user buses
# without the /proc walk.
#
# Each candidate is probed with a real DBus AUTH handshake (NUL +
# AUTH\r\n, expect a reply within 500ms) because connect() alone
# succeeds against stale socket files -- jeepney/libdbus would then
# block forever in SASL on a dead daemon.


def _session_bus_address(user=None):
    """ Build the freedesktop session bus address for the target user.

    Resolution order:
      1. $DBUS_SESSION_BUS_ADDRESS from our own env (only when no
         explicit user is requested -- env reflects the caller's
         session which is wrong when notifying on someone else's behalf).
      2. /run/user/{uid}/bus  (modern systemd user bus -- GNOME,
         Wayland-KDE with systemd integration etc.).
      3. /proc/*/environ scan over the user's live processes for a
         DBUS_SESSION_BUS_ADDRESS -- catches setups that put the
         socket in /tmp/dbus-XXX (SDDM + classic KDE, dbus-launch).
    Returns None if no probe-able bus address is found, which lets
    callers skip the notification instead of hanging in jeepney. """
    if user is None:
        env_addr = os.environ.get('DBUS_SESSION_BUS_ADDRESS')
        if env_addr:
            env_path = _extract_unix_path(env_addr)
            if env_path and _probe_unix_socket(env_path):
                return env_addr
    try:
        uid = _resolve_uid(user)
    except KeyError:
        return None
    runtime_path = f"/run/user/{uid}/bus"
    if _probe_unix_socket(runtime_path):
        return f"unix:path={runtime_path}"
    for candidate in _scan_proc_env(uid):
        candidate_path = _extract_unix_path(candidate)
        if candidate_path and _probe_unix_socket(candidate_path):
            return candidate
    return None


def notify(summary, body="", app_name="otpme-agent",
           icon="folder-remote", timeout_ms=5000,
           urgency="normal", replaces_id=0,
           actions=None, hints=None, user=None):
    """ Send a desktop notification via org.freedesktop.Notifications.

    Returns the notification id (int) on success, or None if the bus
    is unreachable or jeepney is not installed. Never raises.

    Args:
        summary: short headline shown in the notification.
        body: optional longer text; may contain a limited subset of HTML
              depending on the notification daemon.
        app_name: identifier shown by some daemons; used for filtering.
        icon: freedesktop icon name (e.g. "folder-remote") or absolute
              file path to an image.
        timeout_ms: auto-dismiss after this many ms; 0 = no timeout,
                    -1 = let the daemon decide.
        urgency: "low" / "normal" / "critical" (or the integer hint value).
        replaces_id: id of a previous notification to replace in-place;
                     0 = new notification.
        actions: optional list of (action_id, label) pairs.
        hints: optional dict of additional spec hints.
        user: target user the notification is for (username or UID). When
              given, the session bus address is constructed from
              /run/user/{uid}/bus instead of the calling process's env.
              DBus enforces the peer UID; the calling process must
              already be running as that UID (or root with a setuid
              fork) for the connection to succeed.
    """
    try:
        from jeepney import DBusAddress, new_method_call
        from jeepney.io.blocking import open_dbus_connection
    except ImportError:
        return None

    try:
        urgency_value = _resolve_urgency(urgency)
    except OTPmeException as e:
        try:
            config.logger.debug(str(e))
        except Exception:
            pass
        return None

    bus_address = _session_bus_address(user=user)
    if bus_address is None:
        return None

    notify_address = DBusAddress(
        object_path='/org/freedesktop/Notifications',
        bus_name='org.freedesktop.Notifications',
        interface='org.freedesktop.Notifications',
    )

    action_list = []
    if actions:
        for action_id, label in actions:
            action_list.append(action_id)
            action_list.append(label)

    hint_dict = {'urgency': ('y', urgency_value)}
    if hints:
        hint_dict.update(hints)

    msg = new_method_call(
        notify_address,
        'Notify',
        'susssasa{sv}i',
        (
            app_name,
            int(replaces_id),
            icon,
            summary,
            body,
            action_list,
            hint_dict,
            int(timeout_ms),
        ),
    )

    try:
        with open_dbus_connection(bus=bus_address) as conn:
            reply = conn.send_and_get_reply(msg)
    except Exception as e:
        try:
            log_msg = _("Desktop notification dropped: {error}",
                        log=True)[1]
            log_msg = log_msg.format(error=e)
            config.logger.debug(log_msg)
        except Exception:
            pass
        return None

    try:
        return reply.body[0]
    except Exception:
        return None


def close(notification_id, user=None):
    """ Dismiss a previously-issued notification by id. Returns True on
    success, False otherwise. Never raises. """
    try:
        from jeepney import DBusAddress, new_method_call
        from jeepney.io.blocking import open_dbus_connection
    except ImportError:
        return False

    bus_address = _session_bus_address(user=user)
    if bus_address is None:
        return False

    notify_address = DBusAddress(
        object_path='/org/freedesktop/Notifications',
        bus_name='org.freedesktop.Notifications',
        interface='org.freedesktop.Notifications',
    )
    msg = new_method_call(notify_address, 'CloseNotification', 'u',
                          (int(notification_id),))
    try:
        with open_dbus_connection(bus=bus_address) as conn:
            conn.send_and_get_reply(msg)
        return True
    except Exception:
        return False
