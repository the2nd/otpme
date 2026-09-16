# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
""" The mails OTPme writes to users.

A mail is one text: its first line is the subject, then an empty line,
then the body. That is how it is stored where an administrator can
change it -- the info of the SSO accessgroup holds the recovery mail,
one text per language -- and the default below is written into that
info in English when a site is created.

The strings here are marked with _l() rather than _(), see
config.get_translation(): they are read by whoever gets the mail, not
by the log, so they are translated into that user's language.
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

from otpme.lib.exceptions import *

# What the recovery mail may name. Anything else in the text is a typo
# that would only show when somebody needs the mail.
RECOVERY_MAIL_PLACEHOLDERS = [
                            'user_name',
                            'minutes',
                            'reset_url',
                            ]

def default_recovery_mail(language="en"):
    """ The recovery mail as it is shipped, in the given language. """
    _l = config.get_translation(language)
    subject = _l("Account recovery")
    body = _l("Hello,\n\nwe received a request to recover the SSO token for the account '{user_name}'.\n\nTo set up a fresh SSO token, open the following link within the next {minutes} minutes:\n\n{reset_url}\n\nIf you did not request this, you can ignore this message -- your existing token stays untouched.\n")
    return f"{subject}\n\n{body}"

def split_mail_text(text):
    """ The subject and the body of a mail text.

    The first line is the subject when an empty line follows it. A text
    without one is a body alone, and the caller uses its own subject. """
    text = str(text).strip("\n")
    lines = text.split("\n")
    if len(lines) > 2 and not lines[1].strip():
        subject = lines[0].strip()
        body = "\n".join(lines[2:])
        if subject:
            return subject, body
    return None, text

def check_placeholders(text, placeholders):
    """ Raise OTPmeException when the text names something we cannot
    fill in, or is otherwise not formattable. """
    values = {}
    for placeholder in placeholders:
        values[placeholder] = ""
    try:
        str(text).format(**values)
    except KeyError as err:
        msg = _("Unknown placeholder in text: {placeholder}. Valid placeholders: {placeholders}")
        msg = msg.format(placeholder=err.args[0],
                        placeholders=", ".join(placeholders))
        raise OTPmeException(msg) from err
    except Exception as err:
        msg = _("Invalid text: {error}")
        msg = msg.format(error=err)
        raise OTPmeException(msg) from err

def render_mail_text(text, placeholders, **values):
    """ Subject and body of the given mail text, placeholders filled
    in. Raises OTPmeException when the text cannot be formatted, so the
    caller can fall back to the shipped one. """
    check_placeholders(text, placeholders)
    subject, body = split_mail_text(text)
    if subject:
        subject = subject.format(**values)
    body = body.format(**values)
    return subject, body
