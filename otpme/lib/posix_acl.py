# -*- coding: utf-8 -*-
# NOTE: This module was written by claude code!
import os
import stat
import shutil
import tempfile
import posix1e

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib.exceptions import *

# Permission bits of a POSIX.1e ACL entry.
ACL_READ = 4
ACL_WRITE = 2
ACL_EXECUTE = 1

# Map the access modes used by our callers (os.R_OK etc.) to ACL bits.
AMODE_BITS = {
                os.R_OK : ACL_READ,
                os.W_OK : ACL_WRITE,
                os.X_OK : ACL_EXECUTE,
            }

def parse_acl(acl):
    """ Parse a POSIX.1e ACL into a dictionary.

    Returns a dict with the permissions of each entry type:

        user_obj:   permissions of the owner
        users:      permissions per named user (by UID)
        group_obj:  permissions of the owning group
        groups:     permissions per named group (by GID)
        mask:       the mask entry
        other:      permissions of everyone else

    Returns None for a minimal ACL (one without named user/group entries).
    Such an ACL is just a different spelling of the mode bits, so the caller
    has to use them.
    """
    parsed = {
            'user_obj'  : None,
            'users'     : {},
            'group_obj' : None,
            'groups'    : {},
            'mask'      : None,
            'other'     : None,
            }
    for entry in acl:
        perms = 0
        if entry.permset.read:
            perms |= ACL_READ
        if entry.permset.write:
            perms |= ACL_WRITE
        if entry.permset.execute:
            perms |= ACL_EXECUTE
        if entry.tag_type == posix1e.ACL_USER_OBJ:
            parsed['user_obj'] = perms
            continue
        if entry.tag_type == posix1e.ACL_USER:
            parsed['users'][entry.qualifier] = perms
            continue
        if entry.tag_type == posix1e.ACL_GROUP_OBJ:
            parsed['group_obj'] = perms
            continue
        if entry.tag_type == posix1e.ACL_GROUP:
            parsed['groups'][entry.qualifier] = perms
            continue
        if entry.tag_type == posix1e.ACL_MASK:
            parsed['mask'] = perms
            continue
        if entry.tag_type == posix1e.ACL_OTHER:
            parsed['other'] = perms
            continue
    if not parsed['users'] and not parsed['groups']:
        return None
    return parsed

def parse_acl_text(acl_text):
    """ Parse a POSIX.1e ACL text (getfacl syntax) into a dictionary.

    See parse_acl(). Returns None if there is nothing to evaluate (no ACL, an
    unparsable one or a minimal one).
    """
    if not acl_text:
        return None
    try:
        acl = posix1e.ACL(text=acl_text)
    except (IOError, OSError, ValueError, TypeError):
        return None
    return parse_acl(acl)

def read_acl(path):
    """ Read the ACL of the given path.

    See parse_acl(). Reading an ACL does not need read permission on the path,
    so this also works for an entry the process may only search.
    """
    try:
        acl = posix1e.ACL(file=path)
    except (IOError, OSError):
        return None
    return parse_acl(acl)

# Binary ACL attributes we already built, by (acl_text, default).
_acl_xattr_cache = {}

def acl_text_to_xattr(acl_text, default=False):
    """ Get the binary extended attribute of the given ACL text.

    Needed wherever an ACL is only available as text but has to be handed out
    as the attribute a client expects: the backup keeps the default ACL of a
    directory as text, because its meta/ entry is a file and a default ACL
    only exists on a directory.

    We do not build the kernels binary ACL format ourselves. We apply the ACL
    to a temporary directory and read the attribute back, so the kernel does
    the encoding and we cannot get the layout wrong. The result is cached by
    ACL text: a tree usually has very few distinct ACLs, so this runs a
    handful of times per connection, not once per directory.

    Returns None if the ACL cannot be applied, e.g. below a TMPDIR whose
    filesystem has no ACL support.
    """
    if not acl_text:
        return None
    cache_key = (acl_text, default)
    try:
        return _acl_xattr_cache[cache_key]
    except KeyError:
        pass
    acl_xattr = _build_acl_xattr(acl_text, default)
    _acl_xattr_cache[cache_key] = acl_xattr
    return acl_xattr

def _acl_canonical_text(acl):
    """ Render an ACL so that two of them can be compared. """
    acl_text = acl.to_any_text(separator=b",",
                            options=posix1e.TEXT_NUMERIC_IDS)
    return acl_text.decode()

def _build_acl_xattr(acl_text, default):
    """ Let the kernel encode the given ACL. """
    try:
        acl = posix1e.ACL(text=acl_text)
    except (IOError, OSError, ValueError, TypeError):
        return None
    if default:
        acl_type = posix1e.ACL_TYPE_DEFAULT
        xattr_name = "system.posix_acl_default"
    else:
        acl_type = posix1e.ACL_TYPE_ACCESS
        xattr_name = "system.posix_acl_access"
    tmp_dir = None
    try:
        # A directory: only one of those can carry a default ACL. It is
        # created and removed right away, so nothing is left behind even if
        # the process never gets to run its exit handlers.
        tmp_dir = tempfile.mkdtemp(prefix="otpme-acl-")
        acl.applyto(tmp_dir, acl_type)
        acl_xattr = os.getxattr(tmp_dir, xattr_name)
        # Make sure we got what we asked for. A filesystem without ACL
        # support does not fail on every step, so we check instead of
        # handing out something we never verified.
        if default:
            check_acl = posix1e.ACL(filedef=tmp_dir)
        else:
            check_acl = posix1e.ACL(file=tmp_dir)
        if _acl_canonical_text(check_acl) != _acl_canonical_text(acl):
            return None
    except (IOError, OSError):
        return None
    finally:
        if tmp_dir is not None:
            shutil.rmtree(tmp_dir, ignore_errors=True)
    return acl_xattr

def amode_to_acl_perms(amode):
    """ Get the ACL permission bits of the given access mode. """
    perms = 0
    for x_amode in AMODE_BITS:
        if not amode & x_amode:
            continue
        perms |= AMODE_BITS[x_amode]
    return perms

def check_access(mode, uid, gid, acl, user_uid, user_gids, amode,
    is_dir=False):
    """ Check if the given user may access an entry with the given metadata.

    This is the POSIX.1e access check algorithm. It is needed wherever the
    kernel cannot do the check for us, e.g. for the metadata a backup snapshot
    recorded for an entry (which is not the metadata the entry has on disk).

    mode:       the entrys mode (the file type bits are ignored)
    uid/gid:    the entrys owner
    acl:        the entrys ACL as returned by parse_acl() (or None)
    user_uid:   the UID of the user to check
    user_gids:  all GIDs of the user to check (including the primary one)
    amode:      the requested access (os.R_OK, os.W_OK, os.X_OK or os.F_OK)
    is_dir:     True if the entry is a directory
    """
    wanted = amode_to_acl_perms(amode)
    if not wanted:
        # os.F_OK only asks for existence.
        return True

    if user_uid == 0:
        # Root bypasses read/write. Execute needs at least one execute bit,
        # but a directory is always searchable for root.
        if not wanted & ACL_EXECUTE:
            return True
        if is_dir:
            return True
        return bool(mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))

    mode = stat.S_IMODE(mode)
    owner_perms = (mode >> 6) & 0o7
    group_perms = (mode >> 3) & 0o7
    other_perms = mode & 0o7

    if acl is None:
        if user_uid == uid:
            return (wanted & owner_perms) == wanted
        if gid in user_gids:
            return (wanted & group_perms) == wanted
        return (wanted & other_perms) == wanted

    # The mask limits every entry but the owner and other entries.
    mask = acl['mask']
    if mask is None:
        mask = ACL_READ | ACL_WRITE | ACL_EXECUTE

    # The owner entry is not masked.
    if user_uid == uid:
        granted = acl['user_obj']
        if granted is None:
            granted = owner_perms
        return (wanted & granted) == wanted

    # A matching named user entry decides on its own.
    if user_uid in acl['users']:
        granted = acl['users'][user_uid] & mask
        return (wanted & granted) == wanted

    # Every matching group entry may grant the access. Access is denied if
    # entries match but none of them grants the requested permissions.
    group_match = False
    for x_gid in user_gids:
        if x_gid == gid:
            group_match = True
            granted = acl['group_obj']
            if granted is None:
                granted = group_perms
            if (wanted & (granted & mask)) == wanted:
                return True
        if x_gid in acl['groups']:
            group_match = True
            granted = acl['groups'][x_gid] & mask
            if (wanted & granted) == wanted:
                return True
    if group_match:
        return False

    granted = acl['other']
    if granted is None:
        granted = other_perms
    return (wanted & granted) == wanted
