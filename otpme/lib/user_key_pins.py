# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
""" The encrypt public keys of users, written down and held to.

otpme-pass encrypts the key of a password for every member with the
encrypt public key of that member, and that key comes from mgmtd.
Whoever runs mgmtd could hand in a key of their own for a member who is
signed, and read every password written after that.

With PIN_USER_KEYS the key mgmtd sends has to be the one written down
here, or the member gets no key:

  * The key of a user we have never seen is written down by the sync.
    It comes from the realm, so there is nobody to ask. After every
    sync all users this host holds a copy of are looked at, in one
    search of the index, see SyncClient.note_user_keys().
  * A key that differs from the one written down does not replace it.
    The sync says so in its log. Somebody with root takes the new key
    over by hand, with otpme-tool update_user_keys, which shows what it
    is about to change.
  * Nothing is ever taken away by a sync, not even for a user that is
    gone. Whoever controls a node could otherwise delete a user and add
    them again with the same UUID and a key of their own. Pins of users
    that are gone are removed by hand, again with update_user_keys.

On hosts only. A node holds the tree and has no use for otpme-pass:
the passwords are opened where the user sits, and that is a host.

Where things go:

    <spool>/user_keys/<uuid>    the key we hold this user to

Written by the sync, which runs as the OTPme user, and by
update_user_keys, which is root's. Readable by everybody, they are
public keys, and otpme-pass reads them as the user who runs it.
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
from otpme.lib import filetools
from otpme.lib.host_key_pins import read_key
from otpme.lib.host_key_pins import list_uuids

from otpme.lib.exceptions import *

logger = config.logger


def pin_file(user_uuid):
    """ The file that holds the key we hold a user to. """
    return os.path.join(config.user_key_pin_dir, user_uuid)


def get_pin(user_uuid):
    """ The key we hold this user to, or None. """
    return read_key(pin_file(user_uuid))


def write_pin(user_uuid, public_key):
    """ Write down the key we hold this user to.

    Only from update_user_keys and from the sync that brings the first
    key of a user, see the module docstring.
    """
    if not os.path.exists(config.user_key_pin_dir):
        filetools.create_dir(path=config.user_key_pin_dir,
                            user=config.user,
                            group=config.group,
                            mode=0o775)
    filetools.create_file(path=pin_file(user_uuid),
                        content=public_key.strip(),
                        user=config.user,
                        group=config.group,
                        mode=0o664)


def del_pin(user_uuid):
    """ Forget the key of a user. update_user_keys only. """
    path = pin_file(user_uuid)
    if os.path.exists(path):
        filetools.delete(path)


def note_key(user_uuid, public_key):
    """ What the sync does with the key of a user it holds a copy of.

    Returns what happened, as one word, for whoever logs it:

        pinned      there was nothing yet, so this is now the key
        changed     it differs from the one written down, which stays
        unchanged   it is the key we already hold this user to

    A user without a key changes nothing: what is written down stays.
    """
    if not public_key:
        return "unchanged"
    pinned = get_pin(user_uuid)
    if pinned is None:
        write_pin(user_uuid, public_key)
        return "pinned"
    if pinned == public_key.strip():
        return "unchanged"
    return "changed"


def has_pins():
    """ Whether anything is written down yet. """
    return bool(list_uuids(config.user_key_pin_dir))


def all_pins():
    """ Every key we hold a user to, as {uuid: key}. """
    pinned = {}
    for user_uuid in list_uuids(config.user_key_pin_dir):
        key = get_pin(user_uuid)
        if key:
            pinned[user_uuid] = key
    return pinned


def check_keys(recipients):
    """ Split the members by what is written down about their keys.

    Returns (ok, not_pinned, changed): the members whose key is the one
    we hold them to, and the names of the others.
    """
    ok = {}
    not_pinned = []
    changed = []
    for x_uuid, x_recipient in recipients.items():
        pinned = get_pin(x_uuid)
        if pinned is None:
            not_pinned.append(x_recipient['name'])
            continue
        if pinned != x_recipient['public_key'].strip():
            changed.append(x_recipient['name'])
            continue
        ok[x_uuid] = x_recipient
    return ok, not_pinned, changed
