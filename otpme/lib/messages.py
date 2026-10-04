# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import re
import sys
import pprint
from termcolor import colored

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {__name__}")
        msg = msg.format(__name__=__name__)
        print(msg)
except Exception:
    pass

# termcolor knows no orange. 208 is orange in the 256 color palette,
# which a terminal that shows the red and green of termcolor shows too.
ORANGE = "\033[38;5;208m"
# Grey from the same palette, for what is over and needs nothing: 244 is
# dark enough to step back next to the other colors and still readable on
# a light background.
GREY = "\033[38;5;244m"
COLOR_RESET = "\033[0m"

def colored_orange(text):
    """ <text> in orange, for the terminal. """
    return f"{ORANGE}{text}{COLOR_RESET}"

def colored_grey(text):
    """ <text> in grey, for the terminal. """
    return f"{GREY}{text}{COLOR_RESET}"

# What a colour looks like on the way out: ESC [ ... m, which is every
# colour and attribute anything here sets. Not every escape sequence
# there is -- a cursor movement is none of this -- because the only
# thing that has to come out again is what was put in for a terminal.
COLOR_SEQUENCE = re.compile(r'\033\[[0-9;]*m')

def strip_color(text):
    """ <text> without the colours, for something that is not a
    terminal. """
    if not isinstance(text, str):
        return text
    return COLOR_SEQUENCE.sub("", text)

def message(msg, newline=True, sameline=False,
    stderr=False, print_escape=True, prefix=None):
    """ Print a user message to stdout.

    Without the colours where this is not going to a terminal. A
    listing of jobs says in colour which host failed, and mgmtd has no
    terminal to decide that for itself, so it colours the line and the
    client prints it -- and into a pipe that put the escape sequence in
    front of the first field:

        otpme-deploy list --failed | awk '{print $1}'

    handed back a uuid with a colour on it, and the next command did
    not know that job. So what is written to something that is not a
    terminal is written plain.
    """
    print_method = sys.stdout
    if stderr:
        print_method = sys.stderr
    try:
        a_terminal = print_method.isatty()
    except Exception:
        # Something that is not a stream at all. Then it is not a
        # terminal either.
        a_terminal = False
    if not a_terminal:
        msg = strip_color(msg)
    if not isinstance(msg, str):
        msg = pprint.pformat(msg)
    elif print_escape:
        msg = msg.replace("\\", "\\")
        msg = msg.replace("\\0", "\0")
        msg = msg.replace("\\a", "\a")
        msg = msg.replace("\\b", "\b")
        msg = msg.replace("\\f", "\f")
        msg = msg.replace("\\n", "\n")
        msg = msg.replace("\\r", "\r")
        msg = msg.replace("\\t", "\t")
        msg = msg.replace("\\v", "\v")
    if prefix is not None:
        msg = f"{prefix}{msg}"
    if sameline:
        print_method.write('\r')
        print_method.write("\033[K")
        print_method.flush()
        if newline:
            print_method.write(f"{msg}\n")
        else:
            print_method.write(f"{msg}")
    else:
        if newline:
            print_method.write(f"{msg}\n")
        else:
            print_method.write(msg)
    print_method.flush()

def error_message(msg, color=True, **kwargs):
    """ Print a user message to stderr """
    if color:
        msg = colored(msg, 'red')
    message(msg, stderr=True, **kwargs)
