# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
""" The public keys of other hosts, written down and held to.

A remote access session is held against the key the host was joined
with (confd/remote_access.py, the vouch), and that key is read from
this host's copy of the tree. Whoever can change the tree can change it,
and then a session goes wherever they say.

With PIN_HOST_KEYS the copy is not the last word. The key of a host we
have never seen is written down by the sync that brings it. A key that
differs from the one written down does not replace it: the sync says so
in the log and leaves the key that is written down where it is. Somebody
with root takes the key of the tree over by hand, with otpme-tool
update_host_keys, which shows what it is about to change.

Nothing written down is ever taken away by the sync, not even for a
host that is gone: whoever controls a node could otherwise delete a
host and add it again with the same uuid and a key of their own. The
pins of hosts that are gone are removed with update_host_keys as well.

On hosts only. A node holds the tree, and whoever controls it controls
what would be written down there as well; a session started on a node
is held against the key of the tree (rac_client.get_host_public_key()).

Nothing is parked anywhere in between. What a host's key would be is
read from the host object when update_host_keys runs, so what is shown
is the tree as it is at that moment and not what some sync saw.

This is what known_hosts is for ssh, with two differences: the first key
needs no confirmation, because it did not come from the host itself but
from the realm; and what is written down is the key the host was joined
with, not the SSH host key of a session, which is new every time.

Where things go:

    <spool>/host_keys/<uuid>    the key we hold this host to

Written by the sync, which runs as the OTPme user, and by
update_host_keys, which is root's. The directory is group writeable,
because the sync has to be able to put the first key of a host there.
"""
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import filetools

from otpme.lib.exceptions import *

logger = config.logger

# What a file name in here may look like, so nothing but a uuid is read
# as one: these directories are group writeable.
UUID_LEN = 36


def fingerprint(public_key):
    """ What a host key is called when somebody is shown it.

    "SHA256:<base64 without padding>", the way OpenSSH names a key, so
    it reads like the other fingerprints OTPme prints. Over the key as
    it is stored, which is what both ends compare.
    """
    import base64
    import hashlib
    if not public_key:
        return "nothing yet"
    digest = hashlib.sha256(public_key.strip().encode()).digest()
    digest = base64.b64encode(digest).decode().rstrip("=")
    return f"SHA256:{digest}"


def pin_file(host_uuid):
    """ The file that holds the key we hold a host to. """
    return os.path.join(config.host_key_pin_dir, host_uuid)


def read_key(path):
    """ One key from one file, or None. """
    if not os.path.exists(path):
        return None
    try:
        fd = open(path, "r")
        key = fd.read()
        fd.close()
    except Exception as e:
        msg = _("Error reading host key: {path}: {error}")
        msg = msg.format(path=path, error=e)
        raise OTPmeException(msg) from e
    return key.strip() or None


def get_pin(host_uuid):
    """ The key we hold this host to, or None. """
    return read_key(pin_file(host_uuid))


def write_pin(host_uuid, public_key):
    """ Write down the key we hold this host to.

    Only from update_host_keys and from the first sync that brings a
    key, see the module docstring.
    """
    if not os.path.exists(config.host_key_pin_dir):
        filetools.create_dir(path=config.host_key_pin_dir,
                            user=config.user,
                            group=config.group,
                            mode=0o775)
    filetools.create_file(path=pin_file(host_uuid),
                        content=public_key,
                        user=config.user,
                        group=config.group,
                        mode=0o664)


def del_pin(host_uuid):
    """ Forget the key of a host. """
    path = pin_file(host_uuid)
    if os.path.exists(path):
        filetools.delete(path)


def note_key(host_uuid, public_key):
    """ What the sync does with the key of a host it holds a copy of.

    Returns what happened, as one word, for whoever logs it:

        pinned      there was nothing yet, so this is now the key
        changed     it differs from the one written down, which stays
        unchanged   it is the key we already hold this host to

    Nothing is written for a key that changed. It is read off the host
    object again when somebody runs update_host_keys, so there is no
    second copy here that could be out of date by then.

    A host whose key is taken away keeps what was written down. Taking
    it away and setting another is what somebody who controls a node
    would do to get a key of their own past us; a pin goes by hand only,
    with update_host_keys.
    """
    if not public_key:
        return "unchanged"
    pinned = get_pin(host_uuid)
    if pinned is None:
        # The first key of a host, and it did not come from the host
        # itself but from the realm, so there is nobody to ask.
        write_pin(host_uuid, public_key)
        return "pinned"
    if pinned == public_key.strip():
        return "unchanged"
    return "changed"


def list_uuids(path):
    """ The uuids a directory holds, and nothing else. """
    found = []
    if not os.path.exists(path):
        return found
    for name in sorted(os.listdir(path)):
        if len(name) != UUID_LEN:
            continue
        if not stuff.is_uuid(name):
            continue
        if not os.path.isfile(os.path.join(path, name)):
            continue
        found.append(name)
    return found


def all_pins():
    """ Every key we hold a host to, as {uuid: key}. """
    pinned = {}
    for host_uuid in list_uuids(config.host_key_pin_dir):
        key = get_pin(host_uuid)
        if key:
            pinned[host_uuid] = key
    return pinned
