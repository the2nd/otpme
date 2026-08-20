# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
""" Per-object changelog handling. """
import os
import string
import inspect
import threading
from functools import wraps

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import config

from otpme.lib.exceptions import *

# Thread-local recording context. Ensures exactly one changelog entry per
# top-level command: nested/internal decorated calls do not record their own
# entry.
_ctx = threading.local()

def set_pending_detail(text):
    """ Set the (immutable) detail text for the running command.

    Called by OTPmeObject.set_changelog() from within a command method
    (typically at the branch that decides the actual outcome, e.g.
    share.remove_token with/without --keep-share-key). This sets the immutable
    'detail' part of the entry; it is NOT editable later. The editable part is
    the user's --changelog comment. Ignored when called outside of a recording
    context (e.g. from an internal helper that is not the top-level command).
    """
    if getattr(_ctx, "depth", 0) > 0:
        _ctx.detail = text

class ActionFormatter(string.Formatter):
    """ Formatter that renders unset values as an empty string.

    Many commands take optional arguments (e.g. force_group(group_name=None)).
    Rendering them as "None" would be worse than leaving them out, so unknown
    and unset placeholders vanish and the caller collapses the whitespace they
    leave behind. Unset means None or False (some commands default their value
    argument to False, e.g. client.change_login_url()). A bool flag has no
    meaning in an action text anyway, its outcome belongs in set_changelog().
    """
    def get_value(self, key, args, kwargs):
        try:
            value = super().get_value(key, args, kwargs)
        except (KeyError, IndexError):
            return ""
        if value is None or value is False:
            return ""
        return value

action_formatter = ActionFormatter()

def build_action(f, self, f_args, f_kwargs, text):
    """ Build the (immutable) changelog action text of a command.

    The text is written per method (see object_changelog()) and may reference
    the method arguments (and the object itself via {self.xy}) as format
    placeholders, e.g. "add token {token_path}" -> "add token user1/token1".
    The acting token and the object are stored/shown separately.

    Without a text we fall back to the method name. Placeholders are never
    auto generated: which argument is meaningful (and which one is a secret)
    is known by the method, not by us.
    """
    if not text:
        return f.__name__
    if "{" not in text:
        return text
    try:
        sig = inspect.signature(f)
        bound = sig.bind_partial(self, *f_args, **f_kwargs)
        bound.apply_defaults()
        format_args = dict(bound.arguments)
    except Exception:
        format_args = dict(f_kwargs)
        format_args['self'] = self
    try:
        action = action_formatter.vformat(text, (), format_args)
    except Exception:
        return f.__name__
    # Collapse the whitespace unset placeholders left behind.
    action = " ".join(action.split())
    if not action:
        return f.__name__
    return action

def object_changelog(text=None):
    """ Decorator to record a changelog entry for a top-level command.

    Place it as the innermost decorator (directly above the method) so it runs
    inside the object lock/transaction: the appended entry is then persisted by
    the same transaction commit as the command itself.

    Each entry has three parts:
        - action  : immutable text of this decorator (the command).
        - detail  : immutable text the method set via self.set_changelog().
        - comment : editable text from the user's --changelog option.

    text: the immutable action text, written per method. It may reference the
    method arguments as format placeholders, e.g.

        @object_changelog("add token {token_path}")

    Arguments must be referenced explicitly, so secrets (passwords, private
    keys, shared secrets) and noise (PEM blobs) simply stay out of the text.
    Placeholders that are unset (None) render as an empty string. An outcome
    that depends on a branch within the method (e.g. share.remove_token with
    or without --keep-share-key) is recorded by the method itself via
    self.set_changelog().
    """
    def wrapper(f):
        @wraps(f)
        def wrapped(self, *f_args, **f_kwargs):
            # Allow callers to suppress changelog recording by passing
            # changelog=False (analogous to verify_acls=False). We only read it
            # (not pop), so it is still passed to the method and propagates into
            # nested calls, just like verify_acls. When suppressed, any
            # self.set_changelog() the method calls simply has no effect.
            record = f_kwargs.get("changelog", True)
            depth = getattr(_ctx, "depth", 0)
            # Re-entrancy guard: only the outermost decorated call records. A
            # nested (internal) command still runs, but must not leak its own
            # set_changelog() detail into the outer command's entry, so shield
            # the outer pending detail across the nested call.
            if depth > 0:
                saved_detail = getattr(_ctx, "detail", None)
                _ctx.depth = depth + 1
                try:
                    return f(self, *f_args, **f_kwargs)
                finally:
                    _ctx.depth = depth
                    _ctx.detail = saved_detail
            _ctx.depth = 1
            _ctx.detail = None
            # Immutable action text (written per method).
            action = build_action(f, self, f_args, f_kwargs, text)
            try:
                result = f(self, *f_args, **f_kwargs)
            finally:
                pending_detail = getattr(_ctx, "detail", None)
                _ctx.depth = 0
                _ctx.detail = None
            # Do not record failed commands.
            if result is False:
                return result
            # Caller asked to suppress the changelog (changelog=False).
            if not record:
                return result
            # Only tree objects keep a changelog (base command methods are also
            # inherited by non-tree objects like sessions).
            if self.type not in config.tree_object_types:
                return result
            # Respect the per-object/site changelog configuration (changelog).
            # Fail open: keep the audit trail if the config resolution errors out.
            try:
                enabled = self.changelog_enabled()
            except Exception:
                enabled = True
            if not enabled:
                return result
            # Immutable detail set by the method via self.set_changelog().
            detail = pending_detail
            # Editable comment from the user's --changelog option.
            comment = config.changelog
            if not action and not detail and not comment:
                return result
            callback = f_kwargs.get("callback")
            self.add_changelog_entry(action=action,
                                    detail=detail,
                                    comment=comment,
                                    callback=callback)
            return result
        return wrapped
    return wrapper
