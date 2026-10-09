# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
"""Put a message box in front of a user of this host.

A desktop notification (lib/desktop_notify.py) is the right thing for
"your share is mounted": it appears, it goes away, and nobody waits for
it. A message somebody has to read is not that, so this draws a window
with an OK button in the session of the user.

Nothing here draws it itself. The helpers are the ones a desktop brings
anyway and the first one that is installed wins: kdialog on KDE, zenity
on GNOME, the pinentry OTPme needs for smartcards either way, and
xmessage, which has been in x11-utils since before any of the others
existed.

Two things a window needs that a daemon does not have: which display to
draw on, and the authority to draw there. The display comes from the
login session -- the PAM module hands it to the agent at session open
(pam.open_session -> agent1 "set_display") -- and the X authority from
the environment of the processes the user is running, the same walk the
notifications do to find the session bus. The agent runs as the user it
belongs to (one agent per user, see config.get_agent_socket), so there
is nobody to become first.

Nobody waits for the window either. The user may leave it open for an
hour, and the agent has an idled connection to serve in the meantime --
so the helper is started and let go, and what it answers is not read.
Which is also why there is no confirmation anywhere: the OK button
closes the window, and that is all it does.
"""
import os
import pwd
import shutil
import threading

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import config
from otpme.lib import desktop_notify

from otpme.lib.exceptions import *

# What the box is called when the sender did not say.
DEFAULT_TITLE = "OTPme"

# The display to draw on when neither the session nor the user's own
# processes say which one. The first one, which is what a single-seat
# machine has.
DEFAULT_DISPLAY = ":0"


def _assuan_escape(text):
    """ Text as the Assuan protocol of pinentry wants it.

    Percent first, else the escapes of the other characters would be
    escaped again. A line end is %0A because the protocol is line
    based: a raw newline would end the command.
    """
    text = text.replace("%", "%25")
    text = text.replace("\r", "")
    text = text.replace("\n", "%0A")
    return text


def _kdialog_command(binary, title, text):
    return [binary, "--title", title, "--msgbox", text], None


def _zenity_command(binary, title, text):
    # --no-markup, because a message is text and not pango: an
    # ampersand in it would otherwise make zenity complain instead of
    # showing it.
    return [binary, "--info", "--no-markup",
            "--title", title, "--text", text], None


def _pinentry_command(binary, title, text):
    # One button and no entry field, which is what a message box is.
    # SETOK names the button, and a pinentry that does not know the
    # command says so and shows its own label.
    script = (
            f"SETTITLE {_assuan_escape(title)}\n"
            f"SETDESC {_assuan_escape(text)}\n"
            "SETOK OK\n"
            "CONFIRM --one-button\n"
            "BYE\n"
            )
    return [binary], script


def _xmessage_command(binary, title, text):
    # The text through stdin ("-file -"), not as an argument: a message
    # that starts with a dash is an option to xmessage.
    return [binary, "-center", "-title", title,
            "-buttons", "OK", "-default", "OK", "-file", "-"], f"{text}\n"


# In the order they are tried. One per desktop, and xmessage for a host
# that has none of them but an X server.
HELPERS = [
        ("kdialog", _kdialog_command),
        ("zenity", _zenity_command),
        ("pinentry", _pinentry_command),
        ("xmessage", _xmessage_command),
        ]


def find_helper():
    """ The first message box helper this host has.

    Returns (name, path, builder), or (None, None, None) where the host
    has none of them.
    """
    for name, builder in HELPERS:
        binary = shutil.which(name)
        if binary:
            return name, binary, builder
    return None, None, None


def session_env(user, display=None):
    """ What a helper needs to reach the display of that user.

    DISPLAY as the login session knows it, and the X authority of the
    user. Both may also come out of the processes the user is running,
    which is the only source a daemon has when it was started before
    the session existed.
    """
    try:
        pw = pwd.getpwnam(user)
    except KeyError as error:
        msg = _("Unknown user: {user}")
        msg = msg.format(user=user)
        raise OTPmeException(msg) from error

    if not display:
        for candidate in desktop_notify.scan_proc_env(pw.pw_uid, "DISPLAY"):
            display = candidate
            break
    if not display:
        display = DEFAULT_DISPLAY

    xauthority = None
    for candidate in desktop_notify.scan_proc_env(pw.pw_uid, "XAUTHORITY"):
        if os.path.exists(candidate):
            xauthority = candidate
            break
    if not xauthority:
        # Where the server puts it when nobody says otherwise.
        candidate = os.path.join(pw.pw_dir, ".Xauthority")
        if os.path.exists(candidate):
            xauthority = candidate

    env = {
            'DISPLAY'           : display,
            'HOME'              : pw.pw_dir,
            'USER'              : user,
            'LOGNAME'           : user,
            'PATH'              : os.environ.get("PATH", "/usr/bin:/bin"),
            'XDG_RUNTIME_DIR'   : f"/run/user/{pw.pw_uid}",
            }
    if xauthority:
        env['XAUTHORITY'] = xauthority
    # The language of the desktop, so a helper of ours speaks like the
    # rest of it. Only what is set, because an empty LANG is not the
    # same as no LANG.
    for name in ("LANG", "LC_ALL", "LC_MESSAGES"):
        value = os.environ.get(name)
        if value:
            env[name] = value
    return env


def show_message(text, title=None, user=None, display=None):
    """ Draw a message box with an OK button for that user.

    Returns the name of the helper the box was handed to. Raises when
    there is no helper on this host, so a caller can say so and fall
    back to a notification -- which cannot be confirmed, but is better
    than a message nobody ever sees.

    The helper is started and let go. Whoever calls this is not told
    when the user clicked OK, because nothing waits for that.
    """
    from otpme.lib import system_command
    if not text:
        msg = _("Refusing to show a message box without a message.")
        raise OTPmeException(msg)
    if not title:
        title = DEFAULT_TITLE
    if user is None:
        user = config.system_user()

    name, binary, builder = find_helper()
    if name is None:
        msg = _("No message box helper on this host: {helpers}")
        msg = msg.format(helpers=", ".join(x[0] for x in HELPERS))
        raise OTPmeException(msg)

    env = session_env(user, display=display)
    command, stdin_data = builder(binary, title, text)

    # A session of its own, so the box does not go down with whatever
    # stopped the agent, and no pipes for what it says: nobody reads
    # them, and a helper that fills one would hang forever.
    proc = system_command.run(command=command,
                            user=user,
                            env=env,
                            return_proc=True,
                            stdout=None,
                            stderr=None,
                            start_new_session=True)
    if stdin_data:
        try:
            proc.stdin.write(stdin_data.encode())
            proc.stdin.flush()
        except Exception:
            pass
    try:
        proc.stdin.close()
    except Exception:
        pass
    # Somebody has to collect the helper when the user closes the
    # window, else it stays a zombie child of the agent for as long as
    # the agent lives. A thread, because waiting here would mean
    # waiting for the user.
    reaper = threading.Thread(target=proc.wait, daemon=True,
                            name=f"otpme-message-box-{proc.pid}")
    reaper.start()
    return name
