# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
""" The terms of use a user accepts at the SSO portal.

The terms are the info text of the site, one per language. A text counts
only when its first line is "Version: <value>": the version is what is
stored on the user who accepts, so the administrator decides which
change needs a new acceptance and which one is a typo fixed. A text
without that line is ignored as if there was none, and so is an empty
one -- an administrator who forgot the line sees the default text at the
portal instead of their own.

The default is written into the info of a new site in English, and into
an existing one by its site upgrade; every other language falls back to
the English text. The strings are
marked with _l() rather than _(), see config.get_translation(): they are
read by the user at the portal, not by the log.
"""
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import config

# The languages the default text is written into the info of a site in.
# English alone: every other language falls back to it, and a text the
# site does not want in a language would have to be removed by hand.
# The translations of the default are for a site without any text that
# counts, see resolve_terms().
DEFAULT_LANGUAGES = ["en"]

# The version of the default text.
DEFAULT_VERSION = "1"

# The first line of a text that counts.
VERSION_PREFIX = "Version:"

# How long a version may be. It is shown to the administrator and kept
# on every user who accepts.
MAX_VERSION_LEN = 64

def _info_dict(info):
    """ The info of an object as something with get(). It is an
    IncrementalDict on the object, which is no dict. """
    if info is None or not hasattr(info, "get"):
        return {}
    return info

def parse_terms(text):
    """ The version and the body of a terms text, or None.

    None for a text that does not count: no text, an empty one, one
    whose first line is not "Version: <value>", one with an empty or too
    long version, and one with nothing after the version line. """
    if not isinstance(text, str):
        return None
    lines = text.strip("\n").split("\n")
    first_line = lines[0].strip()
    if not first_line.startswith(VERSION_PREFIX):
        return None
    version = first_line[len(VERSION_PREFIX):].strip()
    if not version or len(version) > MAX_VERSION_LEN:
        return None
    body = "\n".join(lines[1:]).strip("\n")
    if not body.strip():
        return None
    return version, body

def default_terms(language="en"):
    """ The terms text as it is shipped, in the given language. """
    _l = config.get_translation(language)
    title = _l("Terms of use")
    body = _l("Your SSO token is personal. Do not give it to anybody, and do not tell anybody its PIN or password.\nYour device tokens, for example for WLAN access, are personal as well. You must not give them or their passwords to others.\nIf you lose a token, or think that somebody else knows its secret, tell your administrator at once.\nYour logins are logged (time, address, application) to protect your account.\nThe terms can change. You will be asked again when they do.\n")
    return f"{VERSION_PREFIX} {DEFAULT_VERSION}\n\n{title}\n\n{body}"

def resolve_terms(info, language="en"):
    """ The terms the user sees: (version, body).

    The text of the language, then the English one, then the shipped
    default in the language. <info> is the info dict of the site. The
    text without a language is the administrator's own note and is never
    taken. """
    info = _info_dict(info)
    for x_language in (language, "en"):
        if not x_language:
            continue
        terms = parse_terms(info.get(x_language))
        if terms:
            return terms
    return parse_terms(default_terms(language))

def missing_languages(info):
    """ The languages of DEFAULT_LANGUAGES whose text does not count. """
    info = _info_dict(info)
    return [x for x in DEFAULT_LANGUAGES if parse_terms(info.get(x)) is None]
