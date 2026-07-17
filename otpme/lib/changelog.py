# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
""" Per-object changelog handling. """
import os
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

# Method arguments that are infrastructure/noise and must not end up in the
# auto generated default text.
IGNORE_ARGS = [
                "verbose_level",
                "force",
                "callback",
                "_caller",
                "lock_timeout",
                "run_policies",
                "lock_reload_on_change",
                "lock_wait_timeout",
                "verify_acls",
                "changelog",
                "no_audit_log",
                ]

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

def build_default_action(f, self, f_args, f_kwargs):
    """ Build the auto generated (immutable) changelog action text.

    Format: "<method> <arg1> <arg2> ...", e.g. "add_token user1/token1". The
    acting token and the object itself are stored/shown separately.
    """
    parts = []
    try:
        sig = inspect.signature(f)
        # Names of *args/**kwargs params (their values are containers/noise).
        var_params = [p.name for p in sig.parameters.values()
                    if p.kind in (p.VAR_POSITIONAL, p.VAR_KEYWORD)]
        bound = sig.bind_partial(self, *f_args, **f_kwargs)
        bound.apply_defaults()
        for name, val in bound.arguments.items():
            if name == "self":
                continue
            if name in var_params:
                continue
            if name in IGNORE_ARGS:
                continue
            # Only include simple identifier-like values (names, paths, numbers).
            # Booleans are skipped: a bare "True"/"False" is meaningless without
            # its parameter name, and flag semantics belong in set_changelog().
            # Complex values (dict/list/objects) would dump noise.
            if isinstance(val, bool):
                continue
            if not isinstance(val, (str, int, float)):
                continue
            if val == "":
                continue
            parts.append(str(val))
    except Exception:
        parts = [str(a) for a in f_args]
    action = f.__name__
    if parts:
        action = "%s %s" % (action, " ".join(parts))
    return action

def object_changelog():
    """ Decorator to record a changelog entry for a top-level command.

    Place it as the innermost decorator (directly above the method) so it runs
    inside the object lock/transaction: the appended entry is then persisted by
    the same transaction commit as the command itself.

    Each entry has three parts:
        - action  : auto generated, immutable default text (this decorator).
        - detail  : immutable text the method set via self.set_changelog().
        - comment : editable text from the user's --changelog option.
    """
    def wrapper(f):
        @wraps(f)
        def wrapped(self, *f_args, **f_kwargs):
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
            try:
                result = f(self, *f_args, **f_kwargs)
            finally:
                pending_detail = getattr(_ctx, "detail", None)
                _ctx.depth = 0
                _ctx.detail = None
            # Do not record failed commands.
            if result is False:
                return result
            # Only tree objects keep a changelog (base command methods are also
            # inherited by non-tree objects like sessions).
            if self.type not in config.tree_object_types:
                return result
            # Respect the per-object/site changelog configuration (changelog /
            # force_changelog parameters). Fail open: keep the audit trail if
            # the config resolution errors out.
            try:
                enabled = self.changelog_enabled()
            except Exception:
                enabled = True
            if not enabled:
                return result
            # Immutable default text.
            action = build_default_action(f, self, f_args, f_kwargs)
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
