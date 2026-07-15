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

def get_password(prompt="Password", description="Password", display=None,
    tty=None, tty_type=None, global_grab=True):
    """ Ask user for a password. """
    with PynEntry(display=display,
                tty=tty,
                tty_type=tty_type,
                global_grab=global_grab) as p:
        p.description = description
        p.prompt = prompt
        try:
            password = p.get_pin()
        except pynentry.PinEntryCancelled:
            return False
        return password
