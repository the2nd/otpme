# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import sys
import pprint
from termcolor import colored

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

def message(msg, newline=True, sameline=False,
    stderr=False, print_escape=True, prefix=None):
    """ Print a user message to stdout """
    print_method = sys.stdout
    if stderr:
        print_method = sys.stderr
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
        msg = "%s%s" % (prefix, msg)
    if sameline:
        print_method.write('\r')
        print_method.write("\033[K")
        print_method.flush()
        if newline:
            print_method.write("%s\n" % msg)
        else:
            print_method.write("%s" % msg)
    else:
        if newline:
            print_method.write("%s\n" % msg)
        else:
            print_method.write(msg)
    print_method.flush()

def error_message(msg, color=True, **kwargs):
    """ Print a user message to stderr """
    if color:
        msg = colored(msg, 'red')
    message(msg, stderr=True, **kwargs)
