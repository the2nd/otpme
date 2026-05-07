# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
"""
Class dispatcher for Session subtypes.

Mirrors otpme.lib.token.get_class so backend.register_object_type can
hand a session_type from the on-disk index back to the matching class.
"""
import os
import importlib

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except Exception:
    pass


# session_type -> (module path, class name). Default falls back to the
# base Session class for any session_type not listed here.
_SUBTYPES = {
    "oidc": ("otpme.lib.session.oidc_session", "OIDCSession"),
}


def get_class(session_type):
    """ Resolve session_type to its concrete class.

    Unknown / unset session_type -> base Session class.
    """
    entry = _SUBTYPES.get(session_type)
    if entry is None:
        from otpme.lib.classes.session import Session
        return Session
    module = importlib.import_module(entry[0])
    return getattr(module, entry[1])
