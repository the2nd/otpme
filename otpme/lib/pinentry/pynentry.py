# -*- coding: utf-8 -*-
import os

import pynentry

from otpme.lib.exceptions import *

# Bogus options send by the upstream PynEntry constructor when we run without
# a controlling terminal (e.g. called from otpme-agent). Pinentry would try to
# open a file literally named "None" which makes GETPIN fail with ENOENT.
BOGUS_OPTIONS = [
                "OPTION ttyname=None",
                "OPTION lc-ctype=None.None",
                ]

class PynEntry(pynentry.PynEntry):
    """ PynEntry with working display/tty handling. """
    # PinMeta metaclass requires _attribs in the class namespace.
    _attribs = pynentry.PynEntry._attribs

    def __init__(self, display=None, tty=None, tty_type=None, **kwargs):
        # Must exist before super().__init__() because it calls self.call().
        self._init_done = False
        super().__init__(display=display, **kwargs)
        self._init_done = True
        if tty:
            self.tty_name = tty
            if not tty_type:
                tty_type = os.environ.get("TERM", "xterm")
            self.tty_type = tty_type

    def call(self, line):
        """ Drop bogus options send by the upstream constructor. """
        if not self._init_done and line in BOGUS_OPTIONS:
            return []
        return super().call(line)

def get_new_password(description="Password", display=None, tty=None,
    tty_type=None, global_grab=True):
    """ Ask user for a new password (with confirmation). """
    with PynEntry(display=display,
                tty=tty,
                tty_type=tty_type,
                global_grab=global_grab) as p:
        p.description = description
        while True:
            p.prompt = 'New password'
            try:
                password1 = p.get_pin()
            except pynentry.PinEntryCancelled:
                return False
            p.prompt = 'Repeat password'
            try:
                password2 = p.get_pin()
            except pynentry.PinEntryCancelled:
                return False
            if password1 == password2:
                return password1
            p.ok_text = 'OK'
            p.cancel_text = 'CANCEL'
            p.description = f'Passwords do not match. Repeat?'
            if not p.get_confirm():
                return False

def get_pinentry_kwargs(executable=None, timeout=None):
    """ The pinentry binary and timeout, where they were given. """
    kwargs = {}
    if executable:
        kwargs['executable'] = executable
    if timeout:
        kwargs['timeout'] = timeout
    return kwargs

def escape_text(text):
    """ Assuan decodes %XX in what it shows, and the upstream class
    escapes only the characters below 33. """
    return text.replace("%", "%25")

def get_password(prompt="Password", description="Password", display=None,
    tty=None, tty_type=None, global_grab=True, executable=None, timeout=None):
    """ Ask user for a password. """
    kwargs = get_pinentry_kwargs(executable=executable, timeout=timeout)
    with PynEntry(display=display,
                tty=tty,
                tty_type=tty_type,
                global_grab=global_grab,
                **kwargs) as p:
        p.description = escape_text(description)
        p.prompt = escape_text(prompt)
        try:
            password = p.get_pin()
        except pynentry.PinEntryError:
            # Cancelled, or timed out.
            return False
        return password

def get_confirm(description, title=None, ok_text=None, cancel_text=None,
    display=None, tty=None, tty_type=None, global_grab=True,
    executable=None, timeout=None):
    """ Ask the user to confirm. True only for OK: a cancel, a timeout
    or any error of pinentry is a no. """
    kwargs = get_pinentry_kwargs(executable=executable, timeout=timeout)
    try:
        with PynEntry(display=display,
                    tty=tty,
                    tty_type=tty_type,
                    global_grab=global_grab,
                    **kwargs) as p:
            if title:
                p.title = escape_text(title)
            p.description = escape_text(description)
            if ok_text:
                p.ok_text = escape_text(ok_text)
            if cancel_text:
                p.cancel_text = escape_text(cancel_text)
            return p.get_confirm()
    except pynentry.PinEntryError:
        return False
