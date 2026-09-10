# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
"""
What the SSO portal calls the things a user enrolls through it.

Every type the portal lets somebody add themselves -- a phone, a
security key, a passkey, a device token -- is named the same way: the
user says what they call the thing, and that one string becomes two
values. The token name has to satisfy the token OID regex and carries a
prefix saying what it is and where it belongs; the label is what the
settings list shows and what the rename dialog offers when the SSO role
moves to another token.

Both live here because they are built from the same string and must not
disagree about it. They started out in tiqr_helpers.py, which is where
the first flow that needed them was, and that is no longer what they
are about.

Like oidc_helpers.py: no backend, no logger, no config, so they can be
unit tested on their own.
"""

# Token names built from a device name. A prefix is not decoration: it
# guarantees the name starts with a letter, and together with stripping
# "-" off the end it makes every generated name match the token name
# regex. The callers build it from the token type plus the portal's
# realm and site, so the name says what the entry is and which list it
# belongs in.


def sanitize_token_name(device_name, prefix=""):
    """ Build a valid token name from what the user typed as a device
    name.

    Restricted to ``[a-z0-9-]``: space and "_" become "-" so word
    boundaries survive, everything else non-alphanumeric is dropped, a
    literal "-" included. Returns None when nothing usable is left --
    the prefix alone does not rescue an empty name, or every unusable
    device name would still produce a valid looking one. """
    if not device_name:
        return None
    name = str(device_name).strip().lower()
    out = []
    for char in name:
        if char.isalnum() and char.isascii():
            out.append(char)
        elif char in " _":
            out.append("-")
    sanitized = "".join(out).strip("-")
    if not sanitized:
        return None
    return f"{prefix}{sanitized}"


def sanitize_device_label(device_name):
    """ What the user typed, as the label the token keeps.

    Not the name -- sanitize_token_name() builds that, and strips the
    separators off the edges on the way. The label is stored as it
    arrives, so without the same treatment the two disagree: the portal
    turns every space into a "-" while the user types (Android's word
    completion appends one to each word it inserts), and "Test " ends up
    as a token named "...-test" carrying the label "test-".

    Only the edges are touched. What somebody calls their phone in the
    middle is theirs. Returns "" for a label that is nothing else. """
    return str(device_name or "").strip().strip("-").strip()
