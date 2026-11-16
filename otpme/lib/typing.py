# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import inspect

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import config

if config.typing_enabled:
    from strongtyping.strong_typing import match_typing
else:
    def match_typing(x):
        return x

def _match_class_typing(cls):
    """ strongtyping's match_class_typing, for the methods of <cls> itself.

    Its own walks dir(cls), which takes in what the class inherits, and
    means to leave classmethods out, but asks getattr() about them, which
    hands it the bound method. So every decorated subclass got the
    classmethods of its parents as plain functions, and a call on the
    class lost cls: backup.backup_object() calls get_backup_data() on the
    class, and under --enable-typing every object without one of its own
    went without a trash copy ("missing 1 required positional argument:
    'file_content'").

    What the class inherits was wrapped where it is defined, if that
    class is decorated as well. """
    for name, value in list(vars(cls).items()):
        if isinstance(value, (classmethod, staticmethod)):
            continue
        if not inspect.isfunction(value):
            continue
        if hasattr(value, "__fe_strng_mtch__"):
            continue
        if not value.__annotations__:
            continue
        parameters = inspect.signature(value).parameters
        # Without arguments there is nothing to check.
        if len(parameters) < 2:
            continue
        try:
            wrapped = match_typing(value, subclass="self" not in parameters)
        except TypeError:
            continue
        setattr(cls, name, wrapped)
    cls._matches_class = True
    return cls

if config.typing_enabled:
    match_class_typing = _match_class_typing
else:
    def match_class_typing(x):
        return x
