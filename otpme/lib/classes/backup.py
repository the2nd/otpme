# -*- coding: utf-8 -*-
# NOTE: This module was written by claude code!
import os
import stat
import gzip
import zlib
import errno
import fcntl
import shutil
import struct
import sqlite3
import fnmatch
import posix1e
import hashlib
from pathlib import Path
from typing import Optional
import time
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers.aead import AESSIV
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes as crypto_hashes

# -- Snap-index binary format constants --
# Header: type_id(B) mode(H) uid(I) gid(I) size(Q) ctime(d) mtime(d) atime(d)
_SNAP_HEADER = struct.Struct('>BHIIQddd')
_SNAP_HEADER_SIZE = _SNAP_HEADER.size  # 43 bytes
_SNAP_TYPE_IDS = {
    'file': 0, 'dir': 1, 'symlink': 2, 'hardlink': 3,
    'blockdev': 4, 'chardev': 5, 'fifo': 6, 'socket': 7,
}
_SNAP_ID_TYPES = {v: k for k, v in _SNAP_TYPE_IDS.items()}
# Offset of ctime (double) inside the header: B+H+I+I+Q = 1+2+4+4+8 = 19
_SNAP_CTIME_OFFSET = 19

# Schema version of the snap-index (PRAGMA user_version).
#   0: snapshot membership in a per snapshot entry_ids.gz file
#   1: snapshot membership in the snap_entries table
#   2: extended attributes in the index entry
#   3: chunk IDs are keyed with the repository key, not a plain hash
_SNAP_SCHEMA_VERSION = 3

# Extended attributes the ACL handling covers already.
_ACL_XATTRS = (
                "system.posix_acl_access",
                "system.posix_acl_default",
            )
# How much of an entries extended attributes we are willing to store.
_MAX_XATTR_BYTES = 65536



def _entry_ctime(val):
    """Extract ctime from a binary snap-index entry without full parse."""
    return struct.unpack_from('>d', val, _SNAP_CTIME_OFFSET)[0]


def _entry_chunk_hashes(val):
    """Extract the chunk IDs from a binary snap-index entry without full parse."""
    if val[0] != _SNAP_TYPE_IDS['file']:
        return []
    off = _SNAP_HEADER_SIZE
    extra_len = struct.unpack_from('>H', val, off)[0]
    off += 2
    if extra_len < 3:
        return []
    num_hashes, hash_len = struct.unpack_from('>HB', val, off)
    if num_hashes == 0 or hash_len == 0:
        return []
    off += 3
    return [val[off + i:off + i + hash_len].hex()
            for i in range(0, num_hashes * hash_len, hash_len)]



try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = "Loading module: {module_name}"
        msg = msg.format(module_name=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import config

from otpme.lib.exceptions import *

try:
    _
except NameError:
    def _(s, log=False):
        if log:
            return s, s
        return s

"""
OTPMe Backup - Deduplicated, encrypted backup with filesystem-native metadata.

Architecture
============

  BackupClient (crypto + file I/O)     BackupServer (storage only)
  ──────────────────────────────────    ──────────────────────────────
   Filesystem read                       get_salt() → bytes
   Metadata collection                   get_key_check() → bytes
   Keyed chunk ID (HMAC)                 block_exists(id) → bool
   zlib compression                      store_block(id, blob)
   AES-GCM encryption                    retrieve_block(id) → blob
   ───── sends encrypted blob ────→      create_snapshot(name)
   ←──── receives encrypted blob ──      write_entry(name, path, meta)
   AES-GCM decryption                    iter_entries(name) → entry...
   zlib decompression                    list_snapshots() → [...]
   File writing + metadata restore       delete_snapshot(name)
                                         gc_orphaned_blocks()

  The server never sees plaintext: it stores blobs the client encrypted and
  never computes a chunk ID itself.  The client in turn leaves the storage
  layout to the server, with one exception -- it reads the snap-index of the
  previous snapshot to find out what changed, see _open_prev_index().

Storage layout
==============

  backup_dir/
  ├── key.salt                   # PBKDF2 salt (600 000 iterations → AES-256 key)
  ├── key.check                  # Blob encrypted with the repository key
  ├── mode                       # Repository mode: "tree" or "pack"
  ├── snap_index.db              # SQLite: entries + snap_entries + snap_meta
  ├── packs/                     # Pack-based encrypted block store
  │   ├── XX/                   #   first 2 hex chars of 6-digit pack ID
  │   │   └── pack-XXXXXX.dat  #   concatenated: 64B chunk ID + 4B len + blob
  │   └── pack_index.db         #   SQLite: chunk ID → (pack_id, offset, length)
  ├── tree/                      # Shared directory tree with all backup entries
  │   ├── etc/                  #   mirrors the original directory structure
  │   │   └── cfg-<snap>        #   files get "-<snap_name>" suffix
  │   └── home/
  │       └── user/
  │           └── doc-<snap>
  └── snapshots/
      └── <name>/
          ├── chunks             # gzip text: one chunk ID per line (GC)
          ├── complete           # Written by finalize_snapshot(), holds the stats
          └── running            # Pidfile, exists while the backup runs

  A non-directory entry has one tree/ file per snapshot, and that file carries
  its filesystem metadata (permissions, ACLs, ownership, timestamps) as actual
  file attributes.  A directory in tree/ is shared by all snapshots, so it can
  not do that: its metadata per snapshot lives in the index.  What is on the
  directory itself is the metadata of the *last* backup, which is what keeps
  the kernel from letting a user into an older snapshot of a directory he lost
  his permissions on.

File content format (tree/ entries)
===================================

  <rel_path>                      ← line 0: original relative path
  <size> <mtime>                  ← line 1 (regular files): decimal size + mtime
  <chunk_id_1>                    ← lines 2+: one chunk ID per line, in order
  <chunk_id_2>
  ...

  A chunk ID is HMAC-SHA256(id_key, plaintext), not a plain hash of the
  plaintext: it is stored in the clear, and a plain hash would let anyone
  with read access confirm whether a known file is in the backup.

  Special entry types use a type marker on line 1:
  SYMLINK, HARDLINK, BLOCKDEV, CHARDEV, FIFO, SOCKET

  A directory has no tree/ entry of its own, so it has no such file: the
  directory itself is the entry, and what it was per snapshot is in the index.

Snapshot deletion & garbage collection
======================================

  1. Read index — for non-dir entries, delete tree/ file (via suffix)
  2. Remove snapshots/<name>/ directory
  3. Clean up empty tree/ directories (bottom-up)
  4. Scan all remaining snapshot chunks files to collect the live chunk IDs
  5. Remove dead IDs from pack index; delete fully empty pack files
  6. Pack-index is updated transactionally

"""

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CHUNK_SIZE     = 4 * 1024 * 1024   # 4 MiB
SALT_SIZE      = 32
KEY_SIZE       = 32                 # AES-256
NONCE_SIZE     = 12                 # AES-GCM
KDF_ITERATIONS = 600_000
COMPRESS_LEVEL = 6                  # zlib 1-9 (6 = good balance)
FLAG_RAW       = b'\x00'           # stored uncompressed
FLAG_ZLIB      = b'\x01'           # stored zlib-compressed

logger = config.logger

# ---------------------------------------------------------------------------
# Crypto helpers (module-level, used by BackupClient)
# ---------------------------------------------------------------------------

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=crypto_hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    key = kdf.derive(password.encode("utf-8"))
    return key


def encrypt_block(key: bytes, plaintext: bytes) -> bytes:
    nonce = os.urandom(NONCE_SIZE)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, None)


def decrypt_block(key: bytes, blob: bytes) -> bytes:
    return AESGCM(key).decrypt(blob[:NONCE_SIZE], blob[NONCE_SIZE:], None)


# ---------------------------------------------------------------------------
# Path encryption (AES-SIV, deterministic)
# ---------------------------------------------------------------------------
# AES-SIV requires a 2×key-size key (256-bit SIV → 512-bit key).
# We derive a separate path-encryption key from the main key via HMAC.

import hmac as _hmac
import base64 as _base64

_PATH_KEY_LABEL = b"otpme-backup-path-encryption-v1"
_ID_KEY_LABEL = b"otpme-backup-chunk-id-v1"


def _derive_path_key(key: bytes) -> bytes:
    """Derive a 64-byte AES-SIV key from the 32-byte main key."""
    # Two HMAC rounds to get 64 bytes (2×32)
    k1 = _hmac.new(key, _PATH_KEY_LABEL + b'\x01', 'sha256').digest()
    k2 = _hmac.new(key, _PATH_KEY_LABEL + b'\x02', 'sha256').digest()
    return k1 + k2


def _derive_id_key(key: bytes) -> bytes:
    """Derive the chunk ID key from the 32-byte main key.

    Kept apart from the key that encrypts the data: the chunk ID is the one
    thing about a chunk that is stored in the clear, so it must not be
    derivable from anything but the repository key.
    """
    return _hmac.new(key, _ID_KEY_LABEL, 'sha256').digest()


def encrypt_path_component(siv: AESSIV, name: str, parent_ct: bytes) -> str:
    """Encrypt a single path component using AES-SIV with parent ciphertext as AD.

    Returns base64url-encoded ciphertext (filesystem safe, no padding).
    """
    ct = siv.encrypt(name.encode('utf-8'), [parent_ct])
    return _base64.urlsafe_b64encode(ct).rstrip(b'=').decode('ascii')


def encrypt_path(siv: AESSIV, rel_path: str) -> str:
    """Encrypt a full relative path, component by component.

    Each component is encrypted with the parent's ciphertext as associated data.
    Returns encrypted path with '/' separators.
    """
    if not rel_path or rel_path == '.':
        return rel_path
    rel_path = rel_path.strip('/')
    if not rel_path:
        return '.'
    parts = rel_path.split('/')
    enc_parts = []
    parent_ct = b''  # root has empty parent context
    for part in parts:
        enc = encrypt_path_component(siv, part, parent_ct)
        # Use the raw ciphertext (before base64) as AD for child
        padded = enc + '=' * (-len(enc) % 4)
        parent_ct = _base64.urlsafe_b64decode(padded.encode('ascii'))
        enc_parts.append(enc)
    return '/'.join(enc_parts)


def decrypt_path(siv: AESSIV, enc_path: str) -> str:
    """Decrypt a full encrypted relative path, component by component."""
    if not enc_path or enc_path == '.':
        return enc_path
    parts = enc_path.split('/')
    dec_parts = []
    parent_ct = b''
    for part in parts:
        padded = part + '=' * (-len(part) % 4)
        ct = _base64.urlsafe_b64decode(padded.encode('ascii'))
        name = siv.decrypt(ct, [parent_ct]).decode('utf-8')
        parent_ct = ct
        dec_parts.append(name)
    return '/'.join(dec_parts)


# ---------------------------------------------------------------------------
# ACL helpers (module-level, used by BackupClient)
# ---------------------------------------------------------------------------

def _format_size(nbytes: int) -> str:
    """Format byte count as human-readable string (e.g. '1.2 GiB')."""
    if nbytes < 1024:
        return f"{nbytes} B"
    for unit in ("KiB", "MiB", "GiB", "TiB"):
        nbytes /= 1024
        if nbytes < 1024 or unit == "TiB":
            return f"{nbytes:.1f} {unit}"


def _get_acl_text(path: str) -> Optional[str]:
    try:
        acl = posix1e.ACL(file=path)
        # Only return ACL text if it contains extended entries (named user/group/mask).
        # Minimal ACLs (user::, group::, other::) are already covered by mode bits.
        has_extended = any(
            e.tag_type in (posix1e.ACL_USER, posix1e.ACL_GROUP, posix1e.ACL_MASK)
            for e in acl
        )
        if not has_extended:
            return None
        return acl.to_any_text(options=posix1e.TEXT_NUMERIC_IDS).decode()
    except (OSError, IOError):
        return None

def _set_acl_text(path: str, acl_text: str) -> None:
    try:
        acl = posix1e.ACL(text=acl_text)
        # Skip minimal ACLs — they only have user::, group::, other::
        # and are already covered by chmod. Applying them can cause EINVAL.
        has_extended = any(
            e.tag_type in (posix1e.ACL_USER, posix1e.ACL_GROUP, posix1e.ACL_MASK)
            for e in acl
        )
        if not has_extended:
            return
        acl.applyto(path)
    except (OSError, IOError) as exc:
        logger.debug("setacl %s: %s", path, exc)
    return

def _get_xattrs(path: str) -> Optional[dict]:
    """Read the extended attributes of an entry.

    Without the POSIX ACLs, which are stored as text of their own.  Symlinks
    are not followed: we back up the link, not what it points at.  Returns
    None if there is nothing to store.

    The values are hex, like the chunk hashes: a meta dict travels to a
    remote backupd as JSON, which has no way to carry raw bytes.  An
    attribute like security.capability -- what /usr/bin/ping has instead of
    a setuid bit -- is binary.
    """
    try:
        names = os.listxattr(path, follow_symlinks=False)
    except OSError as exc:
        if exc.errno not in (errno.ENOTSUP, errno.ENODATA):
            logger.debug("listxattr %s: %s", path, exc)
        return None
    xattrs = {}
    total = 0
    for x_name in names:
        if x_name in _ACL_XATTRS:
            continue
        try:
            value = os.getxattr(path, x_name, follow_symlinks=False)
        except OSError as exc:
            logger.debug("getxattr %s %s: %s", path, x_name, exc)
            continue
        total += len(x_name) + len(value)
        if total > _MAX_XATTR_BYTES:
            logger.warning("Extended attributes exceed %d bytes, storing "
                        "only what fits: %s", _MAX_XATTR_BYTES, path)
            break
        xattrs[x_name] = value.hex()
    if not xattrs:
        return None
    return xattrs

def _set_xattrs(path: str, xattrs: dict) -> None:
    """Apply extended attributes to a restored entry.

    Values are hex, see _get_xattrs().  Has to run after chown(): that drops
    security.capability.
    """
    for x_name in sorted(xattrs):
        try:
            value = bytes.fromhex(xattrs[x_name])
        except ValueError as exc:
            logger.warning("Invalid extended attribute %s on %s: %s",
                        x_name, path, exc)
            continue
        try:
            os.setxattr(path, x_name, value, follow_symlinks=False)
        except OSError as exc:
            logger.debug("setxattr %s %s: %s", path, x_name, exc)
    return

def _pack_xattrs(xattrs: Optional[dict]) -> bytes:
    """Serialise extended attributes: name_len(2) name value_len(4) value."""
    if not xattrs:
        return b''
    parts = []
    for x_name in sorted(xattrs):
        name = x_name.encode('utf-8')
        try:
            value = bytes.fromhex(xattrs[x_name])
        except ValueError as exc:
            logger.warning("Invalid extended attribute %s: %s", x_name, exc)
            continue
        parts.append(struct.pack('>H', len(name)))
        parts.append(name)
        parts.append(struct.pack('>I', len(value)))
        parts.append(value)
    return b''.join(parts)

def _unpack_xattrs(raw: bytes) -> Optional[dict]:
    """Parse what _pack_xattrs() wrote. Returns None if there are none."""
    if not raw:
        return None
    xattrs = {}
    off = 0
    try:
        while off < len(raw):
            name_len = struct.unpack_from('>H', raw, off)[0]
            off += 2
            name = raw[off:off + name_len].decode('utf-8')
            off += name_len
            value_len = struct.unpack_from('>I', raw, off)[0]
            off += 4
            xattrs[name] = raw[off:off + value_len].hex()
            off += value_len
    except (struct.error, IndexError, UnicodeDecodeError) as exc:
        logger.warning("Truncated extended attributes in index entry: %s", exc)
    if not xattrs:
        return None
    return xattrs

def _remove_acl(path: str, default: bool = False) -> None:
    """Drop an extended ACL, leaving the mode bits alone.

    An entry that lost its ACL must not keep the one of the previous backup.
    chmod only recalculates the mask, so a leftover named entry becomes
    effective again as soon as the new mode carries group permissions -- the
    user we just took the ACL away from would still get in.
    """
    if default:
        xattr_name = "system.posix_acl_default"
    else:
        xattr_name = "system.posix_acl_access"
    try:
        os.removexattr(path, xattr_name)
    except OSError as exc:
        if exc.errno in (errno.ENODATA, errno.ENOTSUP):
            # There was none to begin with.
            return
        logger.debug("removeacl %s: %s", path, exc)
    return

def _get_default_acl_text(path: str) -> Optional[str]:
    """Return the default ACL of a directory as single-line text.

    Only directories have one and it grants no access itself: it is the
    template new entries below the directory inherit.  A minimal default ACL
    is kept as well -- unlike the access ACL it is not implied by the mode
    bits, so dropping it would change what gets inherited.  Returns None if
    there is no default ACL.
    """
    try:
        acl = posix1e.ACL(filedef=path)
    except (OSError, IOError):
        return None
    if not acl.valid():
        return None
    return acl.to_any_text(separator=b",",
                        options=posix1e.TEXT_NUMERIC_IDS).decode()

def _set_default_acl_text(path: str, acl_text: str) -> None:
    """Apply a default ACL (directories only)."""
    try:
        acl = posix1e.ACL(text=acl_text)
        acl.applyto(path, posix1e.ACL_TYPE_DEFAULT)
    except (OSError, IOError) as exc:
        logger.debug("setdefaultacl %s: %s", path, exc)
    return

# ---------------------------------------------------------------------------
# Directory walk (sorted, symlink-safe)
# ---------------------------------------------------------------------------

def _walk(path: str, excluded_dirs=None):
    """Yield (full_path, lstat_result) depth-first, directories before contents.

    excluded_dirs: if provided, a *mutable* list of absolute directory path
    prefixes (with trailing /).  The caller appends to this list between
    iterations; directories are not scanned until their turn comes, so
    newly-added exclusions take effect immediately.

    Two-phase approach: directories are first yielded, then pushed as
    "pending scan" markers.  On the next pop the children are scanned,
    giving the caller a chance to add exclusions in between.
    """
    _SCAN = object()  # sentinel: "scan this directory"
    stack = [path]
    while stack:
        current = stack.pop()

        # Phase 2: scan a directory that was already yielded.
        if isinstance(current, tuple) and current[0] is _SCAN:
            dir_path = current[1]
            # Check exclusion (caller may have added it after yield).
            if excluded_dirs:
                abs_prefix = dir_path.rstrip("/") + "/"
                if any(abs_prefix.startswith(d) for d in excluded_dirs):
                    continue
            try:
                children = sorted(os.scandir(dir_path),
                                  key=lambda e: e.name, reverse=True)
            except (PermissionError, OSError) as exc:
                logger.warning("Cannot scan %s: %s", dir_path, exc)
                continue
            for child in children:
                stack.append(child.path)
            continue

        # Phase 1: stat + yield.
        try:
            st = os.lstat(current)
        except (FileNotFoundError, OSError):
            continue
        yield current, st
        if stat.S_ISDIR(st.st_mode):
            # Push scan marker; will be processed on next pop.
            stack.append((_SCAN, current))


# ---------------------------------------------------------------------------
# BackupServer — storage only, no crypto
# ---------------------------------------------------------------------------

class BackupServer:
    """Manages the backup storage: packs/, tree/, snapshots/, the snap-index
    and the repository key material.

    The server never sees plaintext data.  It stores and retrieves
    pre-encrypted blobs identified by a chunk ID the client computes with
    the repository key, and it never computes one itself.
    """

    def __init__(self, backup_dir: str):
        self.root          = Path(backup_dir)
        self.packs_dir     = self.root / "packs"
        self.tree_dir      = self.root / "tree"
        self.snapshots_dir = self.root / "snapshots"
        self.salt_file     = self.root / "key.salt"
        self.key_check_file = self.root / "key.check"
        self.mode_file     = self.root / "mode"
        self.mode          = None  # loaded by _load_mode()
        # The snapshot we are filling, set by create_snapshot() and
        # cleared by finalize_snapshot(). It is the only one the writing
        # methods below accept, so nothing can be written to a snapshot
        # that is finished, nor to the one somebody else is filling: we
        # are made per connection, and create_snapshot() refuses a name
        # that is already there.
        self.snapshot      = None
        self.file_count    = 0
        self.inode_count   = 0
        self._lock_fd      = None
        self._lock_count   = 0
        # Pack-file state
        self._pack_db           = None  # sqlite3.Connection for pack index
        self._active_pack_fd    = None
        self._active_pack_id    = None
        self._active_pack_size  = 0
        self._max_pack_size     = 512 * 1024 * 1024  # 512 MiB
        self._commit_interval = 100000  # commit every N puts
        self._pack_puts_since_commit = 0
        self._snap_puts_since_commit = 0
        # Shared snap-index SQLite (single DB for all snapshots)
        self._snap_db           = None  # sqlite3.Connection
        self._snap_db_readonly  = False # True if opened with mode=ro
        self._snap_id_cache     = {}    # snap_name -> snap_id
        self._active_snap_id    = None  # snap_id of current write session
        self._active_snap_name  = None  # name of current write session
        self._snap_puts_since_commit = 0
        self._chunks_gz         = None  # streaming gzip writer for chunks file
        # Entry cursor state (for chunked iteration)
        self._entry_cursor_cur  = None
        self._entry_cursor_results = None
        self._entry_cursor_snap = None
        self._entry_cursor_snap_id = None
        self._entry_cursor_filter = None
        self._entry_cursor_full = None

    # -- repository locking --

    def lock_repo(self) -> None:
        """Acquire an exclusive lock on the repository (reentrant).

        Uses fcntl.flock on a lockfile — automatically released when
        the file descriptor is closed or the process dies.
        Raises RuntimeError if the repository is locked by another process.
        """
        if self._lock_count > 0:
            self._lock_count += 1
            return
        self.root.mkdir(parents=True, exist_ok=True)
        lock_path = self.root / ".lock"
        fd = open(lock_path, "w")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, IOError) as err:
            fd.close()
            raise RuntimeError("Backup repository is locked by another process.") from err
        fd.write(str(os.getpid()) + "\n")
        fd.flush()
        self._lock_fd = fd
        self._lock_count = 1
        self._load_mode()
        self._open_pack_db()
        self._recover_pack()

    def unlock_repo(self) -> None:
        """Release the repository lock (reentrant)."""
        if self._lock_count > 1:
            self._lock_count -= 1
            return
        self._seal_active_pack()
        self._close_pack_db()
        if self._lock_fd is not None:
            try:
                fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
                self._lock_fd.close()
            except (OSError, IOError):
                pass
            self._lock_fd = None
        self._lock_count = 0

    def _load_mode(self):
        """Read repository mode from mode file, default to 'tree'."""
        if self.mode_file.exists():
            self.mode = self.mode_file.read_text().strip()
        else:
            self.mode = "pack"

    def get_mode(self) -> str:
        """Return the repository mode ('tree' or 'pack')."""
        if self.mode is None:
            self._load_mode()
        return self.mode

    # One entry of one snapshot, by path. The join keeps this an indexed
    # lookup instead of a membership test against the whole snapshot.
    _SNAP_GET_SQL = ("SELECT e.value FROM entries e "
                    "JOIN snap_entries se ON se.entry_id = e.entry_id "
                    "WHERE e.key = ? AND se.snap_id = ? "
                    "ORDER BY e.entry_id DESC LIMIT 1")

    def _connect_snap_db_ro(self) -> sqlite3.Connection:
        """Open a read-only connection to the snap-index.

        For the callers that only read and have no session open. Read-only
        because they also run where we may not write the repository, e.g. on
        a restore mount. Returns None if there is no index yet.
        """
        db_path = self._snap_index_db_path()
        if not os.path.exists(db_path):
            return None
        return sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)

    def _snap_index_get(self, snap_name: str, rel_path: str) -> bytes:
        """Look up a single entry from snap-index SQLite. Returns entry_data or None."""
        snap_id = self._resolve_snap_id(snap_name)
        if snap_id == 0:
            return None
        db = self._snap_db
        if db is None:
            db = self._connect_snap_db_ro()
            if db is None:
                return None
            try:
                row = db.execute(self._SNAP_GET_SQL, (rel_path, snap_id)).fetchone()
            finally:
                db.close()
        else:
            row = db.execute(self._SNAP_GET_SQL, (rel_path, snap_id)).fetchone()
        if row is None:
            return None
        return row[0]

    def _snap_index_get_parsed(self, snap_name: str, rel_path: str) -> dict:
        """Look up a single entry and return parsed dict, or None."""
        val = self._snap_index_get(snap_name, rel_path)
        if val is None:
            return None
        return self._parse_index_entry(val)

    def init_repository(self, mode=None):
        """Create the backup directory structure if it doesn't exist."""
        self.root.mkdir(parents=True, exist_ok=True)
        if not self.mode_file.exists() and mode:
            self.mode_file.write_text(mode)
        self._load_mode()
        self.packs_dir.mkdir(exist_ok=True)
        if self.mode != "pack":
            self.tree_dir.mkdir(exist_ok=True)
        self.snapshots_dir.mkdir(exist_ok=True)

    # -- salt management --

    def get_salt(self) -> bytes:
        """Return the key salt, creating it on first access."""
        if self.salt_file.exists():
            return self.salt_file.read_bytes()
        self.init_repository()
        salt = os.urandom(SALT_SIZE)
        self.salt_file.write_bytes(salt)
        self.salt_file.chmod(0o600)
        return salt

    def get_key_check(self) -> bytes:
        """Return the key check blob, or b'' if the repository has none."""
        if self.key_check_file.exists():
            return self.key_check_file.read_bytes()
        return b''

    def set_key_check(self, blob: bytes) -> None:
        """Store the key check blob of a repository that has none yet.

        Written once and never replaced. Letting it be overwritten would mean
        the first backup with a wrong key simply takes the repository over,
        which is the very thing the check exists to prevent.
        """
        if self.key_check_file.exists():
            msg = _("Repository already has a key check.")
            raise OTPmeException(msg)
        self.init_repository()
        self.key_check_file.write_bytes(blob)
        self.key_check_file.chmod(0o600)

    # -- pack-file helpers --

    def _pack_path(self, pack_id: int) -> Path:
        bucket = f"{pack_id:06x}"[:2]
        return self.packs_dir / bucket / f"pack-{pack_id:06x}.dat"

    def _next_pack_id(self) -> int:
        """Determine the next pack ID from existing pack files."""
        max_id = -1
        if self.packs_dir.exists():
            for bucket_dir in self.packs_dir.iterdir():
                if not bucket_dir.is_dir():
                    continue
                for pack_file in bucket_dir.iterdir():
                    name = pack_file.name
                    if name.startswith("pack-") and name.endswith(".dat"):
                        try:
                            pid = int(name[5:-4], 16)
                            if pid > max_id:
                                max_id = pid
                        except ValueError:
                            pass
        return max_id + 1

    def _ensure_active_pack(self) -> None:
        """Open or rotate the active pack file."""
        if self._active_pack_fd is not None:
            if self._active_pack_size >= self._max_pack_size:
                self._rotate_pack()
            return
        # Open a new pack
        if self._active_pack_id is None:
            self._active_pack_id = self._next_pack_id()
        p = self._pack_path(self._active_pack_id)
        p.parent.mkdir(parents=True, exist_ok=True)
        # Resume existing pack if it was left from a previous session
        if p.exists():
            self._active_pack_size = p.stat().st_size
        else:
            self._active_pack_size = 0
            self.inode_count += 1
        self._active_pack_fd = open(p, 'ab')

    def _rotate_pack(self) -> None:
        """Close the active pack and open a new one."""
        if self._active_pack_fd is not None:
            self._active_pack_fd.close()
            self._active_pack_fd = None
        self._active_pack_id += 1
        self._active_pack_size = 0
        self._ensure_active_pack()

    def _seal_active_pack(self) -> None:
        """Close the active pack file descriptor."""
        if self._active_pack_fd is not None:
            self._active_pack_fd.close()
            self._active_pack_fd = None

    def _recover_pack(self) -> int:
        """Check for uncommitted pack data after a crash and recover it.

        Compares the committed pack state (stored in pack_meta) with the
        actual pack files.  Recovers entries beyond the committed size.

        Returns the number of recovered entries.
        """
        row = self._pack_db.execute(
            "SELECT value FROM pack_meta WHERE key='last_commit'").fetchone()
        if row is None:
            return 0
        committed_pid, committed_size = struct.unpack('>IQ', row[0])

        # Collect all pack files with id >= committed pack, sorted by id.
        packs_to_check = []
        if self.packs_dir.exists():
            for bucket_dir in self.packs_dir.iterdir():
                if not bucket_dir.is_dir():
                    continue
                for pack_file in bucket_dir.iterdir():
                    name = pack_file.name
                    if name.startswith("pack-") and name.endswith(".dat"):
                        try:
                            pid = int(name[5:-4], 16)
                        except ValueError:
                            continue
                        if pid >= committed_pid:
                            packs_to_check.append((pid, pack_file))
        packs_to_check.sort()

        if not packs_to_check:
            return 0

        first_pid, first_path = packs_to_check[0]
        if len(packs_to_check) == 1 and first_pid == committed_pid:
            if first_path.stat().st_size <= committed_size:
                return 0

        recovered = 0
        last_pid = committed_pid
        last_offset = committed_size
        for pid, pack_path in packs_to_check:
            file_size = pack_path.stat().st_size
            start = committed_size if pid == committed_pid else 0
            offset = start
            with open(pack_path, 'rb') as f:
                if start > 0:
                    f.seek(start)
                while offset + 68 <= file_size:
                    header = f.read(68)
                    if len(header) < 68:
                        break
                    h_hex = header[:64].decode('ascii')
                    blob_len = struct.unpack('>I', header[64:68])[0]
                    if offset + 68 + blob_len > file_size:
                        logger.warning(
                            "Truncated entry in pack %06x at "
                            "offset %d, truncating pack file.",
                            pid, offset)
                        break
                    f.seek(blob_len, 1)
                    self._pack_db.execute(
                        "INSERT OR IGNORE INTO pack_index (hash, pack_id, offset, length) "
                        "VALUES (?, ?, ?, ?)",
                        (h_hex, pid, offset, blob_len))
                    recovered += 1
                    offset += 68 + blob_len
            if offset < file_size:
                with open(pack_path, 'r+b') as trunc_f:
                    trunc_f.truncate(offset)
            last_pid = pid
            last_offset = offset

        if recovered:
            self._pack_db.execute(
                "INSERT OR REPLACE INTO pack_meta (key, value) VALUES (?, ?)",
                ('last_commit', struct.pack('>IQ', last_pid, last_offset)))
            self._pack_db.commit()
            logger.info("Recovered %d entries from %d pack(s).",
                        recovered, len(packs_to_check))
        return recovered

    # -- pack index (SQLite) --

    def _pack_index_path(self) -> str:
        """Return path for the pack index SQLite database."""
        return str(self.packs_dir / "pack_index.db")

    def _open_pack_db(self) -> None:
        """Open the pack-index SQLite database."""
        if self._pack_db is not None:
            return
        self.packs_dir.mkdir(parents=True, exist_ok=True)
        path = self._pack_index_path()
        db = sqlite3.connect(path)
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=NORMAL")
        db.execute("PRAGMA cache_size=-65536")
        db.execute("""CREATE TABLE IF NOT EXISTS pack_index (
            hash TEXT PRIMARY KEY,
            pack_id INTEGER NOT NULL,
            offset INTEGER NOT NULL,
            length INTEGER NOT NULL)""")
        db.execute("""CREATE TABLE IF NOT EXISTS pack_meta (
            key TEXT PRIMARY KEY,
            value BLOB NOT NULL)""")
        db.execute("BEGIN")
        self._pack_db = db

    def _close_pack_db(self) -> None:
        """Commit and close the pack-index SQLite database."""
        if self._pack_db is not None:
            # Write commit marker
            if self._active_pack_id is not None:
                self._pack_db.execute(
                    "INSERT OR REPLACE INTO pack_meta (key, value) VALUES (?, ?)",
                    ('last_commit', struct.pack('>IQ', self._active_pack_id,
                                                self._active_pack_size)))
            self._pack_db.commit()
            self._pack_db.close()
            self._pack_db = None

    def load_pack_index(self) -> None:
        """Open the pack-index SQLite database."""
        self._open_pack_db()

    # -- block operations (pack-based) --

    def block_exists(self, h: str) -> bool:
        row = self._pack_db.execute(
            "SELECT 1 FROM pack_index WHERE hash=?", (h,)).fetchone()
        return row is not None

    @staticmethod
    def _is_valid_block_hash(h) -> bool:
        """A chunk ID is a 64-char lowercase hex digest.

        The on-disk pack format hard-codes a 64-byte ID field (store
        writes h + 4-byte length + blob; retrieve seeks offset + 68), so
        a client-supplied h of any other length silently desyncs the
        pack accounting and misaligns later retrieves. Reject anything
        that is not exactly 64 hex chars.
        """
        return (isinstance(h, str)
                and len(h) == 64
                and all(c in "0123456789abcdef" for c in h))

    def store_block(self, h: str, blob: bytes) -> None:
        """Append a pre-encrypted blob to the active pack file."""
        if not self._is_valid_block_hash(h):
            raise OTPmeException(f"Invalid block hash: {h!r}")
        if self.block_exists(h):
            return  # dedup
        self._ensure_active_pack()
        offset = self._active_pack_size
        hash_bytes = h.encode('ascii')
        length_bytes = struct.pack('>I', len(blob))
        self._active_pack_fd.write(hash_bytes + length_bytes + blob)
        self._active_pack_size += 64 + 4 + len(blob)
        self._pack_db.execute(
            "INSERT OR IGNORE INTO pack_index (hash, pack_id, offset, length) "
            "VALUES (?, ?, ?, ?)",
            (h, self._active_pack_id, offset, len(blob)))
        self._pack_puts_since_commit += 1
        if self._pack_puts_since_commit >= self._commit_interval:
            self._active_pack_fd.flush()
            self._pack_db.commit()
            self._pack_db.execute("BEGIN")
            self._pack_puts_since_commit = 0

    def retrieve_block(self, h: str) -> bytes:
        """Return the encrypted blob for a given hash from its pack file."""
        row = self._pack_db.execute(
            "SELECT pack_id, offset, length FROM pack_index WHERE hash=?",
            (h,)).fetchone()
        if row is None:
            raise KeyError(h)
        pack_id, offset, length = row
        with open(self._pack_path(pack_id), 'rb') as f:
            f.seek(offset + 68)  # skip 64-byte hash + 4-byte length
            return f.read(length)

    # -- path helpers --

    def _gen_hash_name(self, name: str, snap_name: str) -> str:
        short = hashlib.sha1(name.encode("utf-8")).hexdigest()[:16]
        tree_name = f"{short}-{snap_name}.longname"
        return tree_name

    def _tree_entry_path(self, rel_path: str, snap_name: str) -> str:
        """Return the full path for a non-directory entry in tree/."""
        self._safe_rel_path(rel_path)
        dirname = os.path.dirname(rel_path)
        basename = os.path.basename(rel_path)
        tree_name = f"{basename}-{snap_name}"
        if len(tree_name.encode("utf-8")) > 255:
            tree_name = self._gen_hash_name(basename, snap_name)
        if dirname:
            candidate = os.path.join(str(self.tree_dir), dirname, tree_name)
        else:
            candidate = os.path.join(str(self.tree_dir), tree_name)
        # Guarantee the composed path stays inside tree_dir even if a
        # legitimate rel_path lands in a directory whose symlink chain
        # would escape the repo.
        self._ensure_in_tree(candidate)
        return candidate

    def _safe_rel_path(self, rel_path: str) -> str:
        """Reject client-supplied rel_paths that would escape tree_dir.

        os.path.join() silently discards its left operand when the right
        operand is absolute, and it does not normalise ".." segments, so
        every write/chown/chmod site that trusted rel_path was a
        traversal primitive. Callers must run this before computing any
        filesystem path from rel_path.
        """
        if not isinstance(rel_path, str):
            raise OTPmeException(
                f"Invalid rel_path type: {type(rel_path).__name__}")
        if "\x00" in rel_path:
            raise OTPmeException("rel_path contains NUL byte")
        if os.path.isabs(rel_path):
            raise OTPmeException(
                f"Refusing absolute rel_path: {rel_path!r}")
        parts = rel_path.replace("\\", "/").split("/")
        if any(p == ".." for p in parts):
            raise OTPmeException(
                f"Refusing rel_path with '..' segment: {rel_path!r}")
        return rel_path

    def _ensure_in_tree(self, abs_path: str) -> str:
        """Reject paths that resolve outside self.tree_dir.

        Second line of defence for callers that compose an absolute path
        from rel_path plus a per-snapshot suffix/basename: even if
        rel_path passed _safe_rel_path, symlinks within the repo could
        still land the final path outside. Returns the canonical path.
        """
        tree_dir_real = os.path.realpath(str(self.tree_dir))
        resolved = os.path.realpath(abs_path)
        if os.path.commonpath([tree_dir_real, resolved]) != tree_dir_real:
            raise OTPmeException(
                f"Path escapes tree_dir: {abs_path!r}")
        return resolved

    @staticmethod
    def _write_gz(path: str, text: str) -> None:
        """Write text as gzip-compressed file."""
        with open(path, 'wb') as fh:
            fh.write(gzip.compress(text.encode('utf-8')))

    @staticmethod
    def _read_gz(path: str) -> str:
        """Read a gzip-compressed (or plain) text file."""
        with open(path, 'rb') as fh:
            raw = fh.read()
        if raw[:2] == b'\x1f\x8b':
            return gzip.decompress(raw).decode('utf-8')
        return raw.decode('utf-8')

    # -- snapshot management --

    @staticmethod
    def _safe_snap_name(snap_name: str) -> str:
        """Reject client-supplied snapshot names that would escape the
        snapshots dir.

        snap_name is used unmodified as a path component (snap_dir /
        snap_chunks_path / ...). pathlib's '/' operator
        discards its left operand on an absolute right operand and never
        normalises "..", so an unchecked snap_name is a traversal
        primitive -- and backup mode runs as root. Restrict it to a
        single, harmless path component (mirrors _safe_rel_path).
        """
        if not isinstance(snap_name, str):
            raise OTPmeException(
                f"Invalid snap_name type: {type(snap_name).__name__}")
        if not snap_name:
            raise OTPmeException("Empty snap_name")
        if "\x00" in snap_name:
            raise OTPmeException("snap_name contains NUL byte")
        if "/" in snap_name or "\\" in snap_name:
            raise OTPmeException(
                f"Refusing snap_name with path separator: {snap_name!r}")
        if snap_name in (".", ".."):
            raise OTPmeException(f"Refusing snap_name: {snap_name!r}")
        return snap_name


    def snap_dir(self, name: str) -> Path:
        self._safe_snap_name(name)
        return self.snapshots_dir / name

    def _snap_index_db_path(self) -> str:
        """Return path for the shared snap-index SQLite database."""
        return str(self.root / "snap_index.db")

    def snap_chunks_path(self, name: str) -> Path:
        """Return path to the snapshot chunks file."""
        return self.snap_dir(name) / "chunks"

    def _open_snap_db(self, readonly: bool = False) -> sqlite3.Connection:
        """Open the shared snap-index SQLite database.

        A read-only connection must not touch the database file: setting the
        journal mode or creating the tables would fail on a repository we may
        only read (a restore mount serves the index with the privileges of the
        mount user). It is opened with mode=ro and query_only, so an attempt
        to write is an error here and not somewhere deep in a query.
        """
        if self._snap_db is not None:
            if not readonly and self._snap_db_readonly:
                msg = _("Snap-index is open read-only.")
                raise OTPmeException(msg)
            return self._snap_db
        db_path = self._snap_index_db_path()
        if readonly and not os.path.exists(db_path):
            return None
        if readonly:
            db = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            db.execute("PRAGMA query_only=1")
        else:
            db = sqlite3.connect(db_path)
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=NORMAL")
        db.execute("PRAGMA cache_size=-65536")  # 64 MiB cache
        self._snap_db_readonly = readonly
        if readonly:
            self._check_snap_schema(db, readonly=True)
        else:
            db.execute("""CREATE TABLE IF NOT EXISTS entries (
                entry_id INTEGER PRIMARY KEY,
                key TEXT NOT NULL,
                value BLOB NOT NULL)""")
            db.execute("CREATE INDEX IF NOT EXISTS idx_entries_key ON entries(key)")
            db.execute("""CREATE TABLE IF NOT EXISTS snap_meta (
                snap_name TEXT PRIMARY KEY,
                snap_id INTEGER NOT NULL)""")
            db.execute("""CREATE TABLE IF NOT EXISTS name_map (
                hmac_hex TEXT PRIMARY KEY,
                enc_name BLOB NOT NULL)""")
            # Which entry belongs to which snapshot. Answering that for one
            # path has to be a single indexed query: we must not need the
            # whole membership of a snapshot in memory to serve one lookup.
            db.execute("""CREATE TABLE IF NOT EXISTS snap_entries (
                snap_id INTEGER NOT NULL,
                entry_id INTEGER NOT NULL,
                PRIMARY KEY (snap_id, entry_id)) WITHOUT ROWID""")
            # The other direction: is this entry still referenced anywhere?
            db.execute("CREATE INDEX IF NOT EXISTS idx_snap_entries_entry ON snap_entries(entry_id)")
            self._check_snap_schema(db)

        self._snap_db = db
        return db

    def _check_snap_schema(self, db, readonly: bool = False) -> None:
        """Stamp the snap-index schema version and refuse an older one.

        There is no migration, in either direction: a repository of an older
        schema has to be created anew. We say that instead of answering every
        lookup with "not found", which would look like an empty snapshot
        rather than a repository we cannot read. See _SNAP_SCHEMA_VERSION for
        what changed when.

        A read-only connection only checks: an empty repository it cannot
        stamp is nothing to complain about either.
        """
        version = db.execute("PRAGMA user_version").fetchone()[0]
        if version >= _SNAP_SCHEMA_VERSION:
            return
        try:
            row = db.execute("SELECT entry_id FROM entries LIMIT 1").fetchone()
        except sqlite3.OperationalError:
            # No entries table yet -> nothing was ever written.
            return
        if row is not None:
            msg = _("Repository uses snap-index schema {version}, expected {expected}. It has to be created anew.")
            msg = msg.format(version=version, expected=_SNAP_SCHEMA_VERSION)
            raise OTPmeException(msg)
        if readonly:
            return
        db.execute(f"PRAGMA user_version = {_SNAP_SCHEMA_VERSION}")

    def _get_snap_id(self, snap_name: str) -> int:
        """Get numeric snap_id for a snapshot name. Creates one if missing."""
        if snap_name in self._snap_id_cache:
            return self._snap_id_cache[snap_name]
        db = self._snap_db
        row = db.execute("SELECT snap_id FROM snap_meta WHERE snap_name=?",
                         (snap_name,)).fetchone()
        if row is not None:
            self._snap_id_cache[snap_name] = row[0]
            return row[0]
        # Assign new ID
        row = db.execute("SELECT MAX(snap_id) FROM snap_meta").fetchone()
        new_id = (row[0] or 0) + 1
        db.execute("INSERT INTO snap_meta (snap_name, snap_id) VALUES (?, ?)",
                   (snap_name, new_id))
        self._snap_id_cache[snap_name] = new_id
        return new_id

    def _resolve_snap_id(self, snap_name: str) -> int:
        """Get snap_id (no creation). Returns 0 if not found."""
        if snap_name in self._snap_id_cache:
            return self._snap_id_cache[snap_name]
        db = self._snap_db
        if db is None:
            db = self._connect_snap_db_ro()
            if db is None:
                return 0
            try:
                row = db.execute("SELECT snap_id FROM snap_meta WHERE snap_name=?",
                                 (snap_name,)).fetchone()
                if row is None:
                    return 0
                self._snap_id_cache[snap_name] = row[0]
                return row[0]
            finally:
                db.close()
        row = db.execute("SELECT snap_id FROM snap_meta WHERE snap_name=?",
                         (snap_name,)).fetchone()
        if row is None:
            return 0
        self._snap_id_cache[snap_name] = row[0]
        return row[0]

    def _open_snap_session(self, snap_name: str) -> None:
        """Open a shared snap-index SQLite session for snap_name."""
        if self._active_snap_id is not None:
            return
        self._open_snap_db()
        self._snap_db.execute("BEGIN")
        self._active_snap_id = self._get_snap_id(snap_name)
        self._active_snap_name = snap_name
        self._snap_puts_since_commit = 0
        # Open streaming gzip writer for chunks file
        chunks_path = self.snap_chunks_path(snap_name)
        self._chunks_gz = gzip.open(str(chunks_path), 'wt')

    def _close_snap_session(self) -> None:
        """Commit and close the active snap-index SQLite session."""
        if self._chunks_gz is not None:
            self._chunks_gz.close()
            self._chunks_gz = None
        self._active_snap_name = None
        if self._snap_db is not None:
            self._snap_db.commit()
            self._snap_db.close()
            self._snap_db = None
            self._snap_db_readonly = False
        self._active_snap_id = None
        self._snap_id_cache = {}

    def _snap_periodic_commit(self) -> None:
        """Periodic commit of snap writes."""
        self._snap_puts_since_commit += 1
        if self._snap_puts_since_commit >= self._commit_interval:
            self._snap_db.commit()
            self._snap_db.execute("BEGIN")
            self._snap_puts_since_commit = 0

    def _snap_index_put(self, snap_name: str, rel_path: str, entry_data: bytes) -> None:
        """Write a binary entry to the snap-index SQLite.

        Always inserts a new entry row and links it to the snapshot.
        Orphaned old entries (same key, no snap reference) are cleaned
        up during snapshot deletion.
        """
        snap_id = self._active_snap_id
        if snap_id is None:
            snap_id = self._resolve_snap_id(snap_name)
            if snap_id == 0:
                raise RuntimeError(f"No snap_id for {snap_name}")
        self._snap_periodic_commit()
        cur = self._snap_db.execute(
            "INSERT INTO entries (key, value) VALUES (?, ?)",
            (rel_path, entry_data))
        entry_id = cur.lastrowid
        self._snap_db.execute(
            "INSERT OR IGNORE INTO snap_entries (snap_id, entry_id) VALUES (?, ?)",
            (snap_id, entry_id))
        # Stream the chunk IDs to the chunks file
        if self._chunks_gz is not None:
            for h in _entry_chunk_hashes(entry_data):
                self._chunks_gz.write(h + '\n')

    def _snap_index_link(self, snap_name: str, rel_path: str,
                         from_snap: str = None) -> None:
        """Link an unchanged entry to a new snapshot.

        Finds the entry_id for the given key in from_snap (or the latest
        entry_id if from_snap is not given) and links it to the new snapshot.
        """
        snap_id = self._active_snap_id
        if snap_id is None:
            snap_id = self._resolve_snap_id(snap_name)
            if snap_id == 0:
                raise RuntimeError(f"No snap_id for {snap_name}")
        self._snap_periodic_commit()
        # Find entry_id: prefer the one from from_snap, fall back to latest
        entry_id = None
        if from_snap is not None:
            from_snap_id = self._resolve_snap_id(from_snap)
            if from_snap_id != 0:
                row = self._snap_db.execute(
                    "SELECT e.entry_id FROM entries e "
                    "JOIN snap_entries se ON se.entry_id = e.entry_id "
                    "WHERE e.key = ? AND se.snap_id = ? "
                    "ORDER BY e.entry_id DESC LIMIT 1",
                    (rel_path, from_snap_id)).fetchone()
                if row is not None:
                    entry_id = row[0]
        if entry_id is None:
            row = self._snap_db.execute(
                "SELECT entry_id FROM entries WHERE key=? ORDER BY entry_id DESC LIMIT 1",
                (rel_path,)).fetchone()
            if row is None:
                return
            entry_id = row[0]
        self._snap_db.execute(
            "INSERT OR IGNORE INTO snap_entries (snap_id, entry_id) VALUES (?, ?)",
            (snap_id, entry_id))
        # Stream the chunk IDs to the chunks file
        if self._chunks_gz is not None:
            val = self._snap_db.execute(
                "SELECT value FROM entries WHERE entry_id=?",
                (entry_id,)).fetchone()[0]
            for h in _entry_chunk_hashes(val):
                self._chunks_gz.write(h + '\n')

    # All entries of one snapshot, ordered by path. Ordering by entry_id
    # within a path lets the reader keep the last row of each path group,
    # which is the same "latest wins" rule _snap_index_get() applies.
    _SNAP_ITER_SQL = ("SELECT e.key, e.value FROM snap_entries se "
                    "JOIN entries e ON e.entry_id = se.entry_id "
                    "WHERE se.snap_id = ? "
                    "ORDER BY e.key, e.entry_id")
    _SNAP_ITER_FILTER_SQL = ("SELECT e.key, e.value FROM entries e "
                    "JOIN snap_entries se ON se.entry_id = e.entry_id "
                    "WHERE se.snap_id = ? "
                    "AND (e.key = ? OR (e.key > ? AND e.key < ?)) "
                    "ORDER BY e.key, e.entry_id")

    @staticmethod
    def _iter_latest_per_key(rows):
        """Yield (key, value) keeping the last row of each key group."""
        last_key = None
        last_val = None
        for key, val in rows:
            if last_key is not None and key != last_key:
                yield last_key, last_val
            last_key = key
            last_val = val
        if last_key is not None:
            yield last_key, last_val

    def _iter_snap_index(self, snap_name: str):
        """Yield (rel_path, entry_data_bytes) tuples for a snapshot from SQLite."""
        snap_id = self._resolve_snap_id(snap_name)
        if snap_id == 0:
            return
        # Use the connection we already have: after a privilege drop we could
        # not open the repository a second time.
        db = self._snap_db
        own_db = False
        if db is None:
            db = self._connect_snap_db_ro()
            if db is None:
                return
            own_db = True
        try:
            rows = db.execute(self._SNAP_ITER_SQL, (snap_id,))
            yield from self._iter_latest_per_key(rows)
        finally:
            if own_db:
                db.close()


    def read_chunks_file(self, snap_name: str) -> set:
        """Read the chunks file and return a set of chunk IDs."""
        return set(self.iter_chunks_file(snap_name))

    def iter_chunks_file(self, snap_name: str):
        """Yield the chunk IDs from the chunks file one at a time (streaming)."""
        chunks_path = self.snap_chunks_path(snap_name)
        if not chunks_path.exists():
            return
        try:
            with gzip.open(str(chunks_path), 'rt') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        yield line
        except EOFError:
            pass

    @staticmethod
    def _build_index_entry(meta: dict) -> bytes:
        """Build a binary snap-index value from a meta dict.

        Format: 43-byte header + 2-byte extra_len + extra + 2-byte acl_len +
        acl + 2-byte default_acl_len + default_acl + 4-byte xattrs_len +
        xattrs.  The xattrs length is 4 bytes because a single attribute can
        hold 64 KiB and an entry can have several.
        Header: type_id(B) mode(H) uid(I) gid(I) size(Q) ctime(d) mtime(d) atime(d)
        """
        entry_type = meta["type"]
        type_id = _SNAP_TYPE_IDS[entry_type]
        size = meta.get("size", 0) if entry_type == "file" else 0
        header = _SNAP_HEADER.pack(
            type_id,
            meta['mode'],
            meta['uid'],
            meta['gid'],
            size,
            float(meta.get('ctime', 0)),
            float(meta.get('mtime', 0)),
            float(meta.get('atime', 0)),
        )
        # Type-specific extra data
        if entry_type == 'symlink':
            extra = meta.get('symlink_target', '').encode('utf-8')
        elif entry_type == 'hardlink':
            extra = meta.get('link_target', '').encode('utf-8')
        elif entry_type in ('blockdev', 'chardev'):
            extra = struct.pack('>II', meta.get('devmajor', 0), meta.get('devminor', 0))
        elif entry_type == 'file':
            chunk_hashes = meta.get('chunk_hashes', [])
            if chunk_hashes:
                raw_hashes = b''.join(bytes.fromhex(h) for h in chunk_hashes)
                hash_len = len(raw_hashes) // len(chunk_hashes)
                extra = struct.pack('>HB', len(chunk_hashes), hash_len) + raw_hashes
            else:
                extra = struct.pack('>HB', 0, 0)
        else:
            extra = b''
        # ACL
        acl = (meta.get('acl', '') or '').encode('utf-8')
        default_acl = (meta.get('default_acl', '') or '').encode('utf-8')
        xattrs = _pack_xattrs(meta.get('xattrs'))
        return (header
                + struct.pack('>H', len(extra)) + extra
                + struct.pack('>H', len(acl)) + acl
                + struct.pack('>H', len(default_acl)) + default_acl
                + struct.pack('>I', len(xattrs)) + xattrs)

    @staticmethod
    def _parse_index_entry(val: bytes) -> Optional[dict]:
        """Parse a binary snap-index value into a dict.

        Returns dict with type, mode, uid, gid, size, ctime, mtime, atime,
        and optionally symlink_target, link_target, devmajor, devminor,
        chunk_hashes, acl, default_acl, xattrs.
        Returns None if data is too short.
        """
        if len(val) < _SNAP_HEADER_SIZE + 2:
            return None
        type_id, mode, uid, gid, size, ctime, mtime, atime = _SNAP_HEADER.unpack_from(val)
        entry_type = _SNAP_ID_TYPES.get(type_id)
        if entry_type is None:
            return None
        entry = {
            'type': entry_type,
            'mode': mode,
            'uid': uid,
            'gid': gid,
            'size': size,
            'ctime': ctime,
            'mtime': mtime,
            'atime': atime,
        }
        off = _SNAP_HEADER_SIZE
        extra_len = struct.unpack_from('>H', val, off)[0]
        off += 2
        extra_data = val[off:off + extra_len]
        off += extra_len

        if entry_type == 'symlink':
            entry['symlink_target'] = extra_data.decode('utf-8')
        elif entry_type == 'hardlink':
            entry['link_target'] = extra_data.decode('utf-8')
        elif entry_type in ('blockdev', 'chardev') and len(extra_data) >= 8:
            entry['devmajor'], entry['devminor'] = struct.unpack('>II', extra_data)
        elif entry_type == 'file' and len(extra_data) >= 3:
            num_hashes, hash_len = struct.unpack_from('>HB', extra_data)
            if num_hashes > 0 and hash_len > 0:
                raw = extra_data[3:]
                entry['chunk_hashes'] = [
                    raw[i:i + hash_len].hex()
                    for i in range(0, num_hashes * hash_len, hash_len)
                ]

        # ACL
        if off + 2 <= len(val):
            acl_len = struct.unpack_from('>H', val, off)[0]
            off += 2
            if acl_len > 0 and off + acl_len <= len(val):
                entry['acl'] = val[off:off + acl_len].decode('utf-8')
            off += acl_len
        # Default ACL (directories only).
        if off + 2 <= len(val):
            default_acl_len = struct.unpack_from('>H', val, off)[0]
            off += 2
            if default_acl_len > 0 and off + default_acl_len <= len(val):
                entry['default_acl'] = val[off:off + default_acl_len].decode('utf-8')
            off += default_acl_len
        # Extended attributes. Only a pack mode backup collects them, so in
        # tree mode the field is there but empty.
        if off + 4 <= len(val):
            xattrs_len = struct.unpack_from('>I', val, off)[0]
            off += 4
            if xattrs_len > 0 and off + xattrs_len <= len(val):
                entry['xattrs'] = _unpack_xattrs(val[off:off + xattrs_len])
        return entry

    def get_snap_index_info(self, snap_name: str = None) -> dict:
        """Return size and fingerprint of the shared snap-index SQLite DB.

        Returns dict with 'size' (file size) and 'fingerprint' (string
        that changes whenever the DB content changes).
        Performs a WAL checkpoint first so the .db file contains all data.
        """
        db_path = self._snap_index_db_path()
        if not os.path.exists(db_path):
            return {'size': 0, 'fingerprint': ''}
        db = sqlite3.connect(db_path)
        try:
            db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            row = db.execute("SELECT COUNT(*) FROM entries").fetchone()
            entries = row[0] if row else 0
        finally:
            db.close()
        size = os.path.getsize(db_path)
        mtime = os.path.getmtime(db_path)
        fp = f"{entries}:{size}:{mtime}"
        return {'size': size, 'fingerprint': fp}

    def get_snap_index_size(self, snap_name: str) -> int:
        """Return the file size of the shared snap-index SQLite DB in bytes."""
        return self.get_snap_index_info(snap_name)['size']

    def get_snap_index_chunk(self, snap_name: str, offset: int, chunk_size: int) -> bytes:
        """Read a zlib-compressed chunk from the snap-index SQLite DB file."""
        db_path = self._snap_index_db_path()
        with open(db_path, 'rb') as f:
            f.seek(offset)
            raw = f.read(chunk_size)
        return zlib.compress(raw, 1)

    def create_snapshot(self, name: str) -> None:
        """Create the snapshot directory and open its index session.

        A snapshot is written once. Handing out a name that is already
        there would open it for writing again -- a finished one included,
        whose entries somebody is relying on -- so a name is taken or it
        is free, and one that broke off half way is taken as well. A
        backup that has to be repeated takes a new name.
        """
        if self.snap_dir(name).exists():
            msg = f"Snapshot exists: {name}"
            raise OTPmeException(msg)
        self.snapshot = name
        self.file_count = 0
        self.inode_count = 0
        self.ref_count = 0
        self.start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.snap_dir(name).mkdir(parents=True, exist_ok=True)
        # Open snap-index session for this snapshot
        self._open_snap_session(name)

    def check_writable(self, name: str) -> None:
        """Make sure we may write to the given snapshot.

        Ours is the one create_snapshot() opened and finalize_snapshot()
        has not closed yet. Any other name is either a snapshot that is
        finished -- whose entries somebody is relying on -- or one that
        belongs to whoever is filling it.
        """
        if name == self.snapshot:
            return
        if self.snapshot is None:
            msg = f"No snapshot to write to: {name}"
        else:
            msg = f"Not our snapshot: {name} (we hold {self.snapshot})"
        raise OTPmeException(msg)

    def set_running(self, name: str) -> None:
        """Write a pidfile to mark the snapshot as currently running."""
        self.check_writable(name)
        pidfile = self.snap_dir(name) / "running"
        pidfile.write_text(str(os.getpid()))

    def clear_running(self, name: str) -> None:
        """Remove the running pidfile."""
        pidfile = self.snap_dir(name) / "running"
        if pidfile.exists():
            pidfile.unlink()

    def is_running(self, name: str) -> bool:
        """Check if a snapshot backup is currently running via pidfile.

        Returns True if the pidfile exists and the PID is alive.
        Removes stale pidfiles automatically.
        """
        pidfile = self.snap_dir(name) / "running"
        if not pidfile.exists():
            return False
        try:
            pid = int(pidfile.read_text().strip())
        except (ValueError, OSError):
            return True
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            # Process gone — stale pidfile
            logger.warning("Removing stale pidfile: %s", pidfile)
            try:
                pidfile.unlink()
            except OSError:
                pass
            return False
        except PermissionError:
            # Process exists but we can't signal it
            return True

    def finalize_snapshot(self, name: str,
                          total_bytes: int = 0,
                          stored_bytes: int = 0) -> None:
        """Mark a snapshot as complete and write stats from internal counters."""
        self.check_writable(name)
        # From here on it is finished, so we hold nothing we may write
        # to any more. Done before the work below: whether marking it
        # complete succeeds or not, it is not ours to write to.
        self.snapshot = None
        self._close_snap_session()
        if self._pack_db is not None:
            self._pack_db.commit()
        self._seal_active_pack()
        self.clear_running(name)
        marker = self.snap_dir(name) / "complete"
        end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        start_time = getattr(self, 'start_time', end_time)
        stats = {
            "files": self.file_count,
            "inodes": self.inode_count,
            "start_time": start_time,
            "end_time": end_time,
            "total_bytes": total_bytes,
            "stored_bytes": stored_bytes,
        }
        lines = [f"{k}={v}" for k, v in stats.items()]
        marker.write_text("\n".join(lines) + "\n")

    def read_complete_stats(self, name: str) -> dict:
        """Read stats from the complete marker file.

        Returns dict with keys like files, inodes, refs, or empty dict.
        """
        marker = self.snap_dir(name) / "complete"
        if not marker.exists():
            return {}
        content = marker.read_text().strip()
        if not content:
            return {}
        result = {}
        for line in content.split("\n"):
            if "=" in line:
                k, v = line.split("=", 1)
                try:
                    result[k] = int(v)
                except ValueError:
                    result[k] = v
        return result

    def is_complete(self, name: str) -> bool:
        """Check if a snapshot was completed successfully."""
        return (self.snap_dir(name) / "complete").exists()

    def write_entry(self, snap_name: str, rel_path: str, meta: dict) -> None:
        """Create a single entry in the snapshot.

        For directories: creates the dir in tree/ (shared by all snapshots).
        For all other types: creates a file in tree/<dir>/<name>-<snap>.

        Content format of that file:
            Line 1: relative path
            Line 2+: type-specific data

        Only creates the filesystem object — does NOT apply metadata.
        Call set_entry_metadata() after write_entry().  For directories,
        defer the call until all files are written (deepest-first) so
        that tree/ directory mtimes are not clobbered.
        """
        self.check_writable(snap_name)
        self._safe_rel_path(rel_path)
        entry_type = meta["type"]

        if self.mode != "pack":
            if entry_type == "dir":
                # A directory in tree/ is shared by all snapshots, so it can
                # not carry the metadata of this one. That lives in the index.
                tree_dir_path = os.path.join(str(self.tree_dir), rel_path) if rel_path != "." else str(self.tree_dir)
                self._ensure_in_tree(tree_dir_path)
                os.makedirs(tree_dir_path, exist_ok=True)
                self.inode_count += 1

            elif entry_type == "symlink":
                tree_path = self._tree_entry_path(rel_path, snap_name)
                self._ensure_in_tree(tree_path)
                os.makedirs(os.path.dirname(tree_path), exist_ok=True)
                self._write_gz(tree_path, f"{rel_path}\nSYMLINK\n{meta['symlink_target']}\n")
                self.file_count += 1
                self.inode_count += 1

            elif entry_type == "hardlink":
                tree_path = self._tree_entry_path(rel_path, snap_name)
                self._ensure_in_tree(tree_path)
                os.makedirs(os.path.dirname(tree_path), exist_ok=True)
                self._write_gz(tree_path, f"{rel_path}\nHARDLINK\n{meta['link_target']}\n")
                self.file_count += 1
                self.inode_count += 1

            elif entry_type in ("blockdev", "chardev"):
                tree_path = self._tree_entry_path(rel_path, snap_name)
                self._ensure_in_tree(tree_path)
                os.makedirs(os.path.dirname(tree_path), exist_ok=True)
                self._write_gz(tree_path, f"{rel_path}\n{entry_type.upper()}\n{meta['devmajor']} {meta['devminor']}\n")
                self.file_count += 1
                self.inode_count += 1

            elif entry_type in ("fifo", "socket"):
                tree_path = self._tree_entry_path(rel_path, snap_name)
                self._ensure_in_tree(tree_path)
                os.makedirs(os.path.dirname(tree_path), exist_ok=True)
                self._write_gz(tree_path, f"{rel_path}\n{entry_type.upper()}\n")
                self.file_count += 1
                self.inode_count += 1

            elif entry_type == "file":
                tree_path = self._tree_entry_path(rel_path, snap_name)
                self._ensure_in_tree(tree_path)
                os.makedirs(os.path.dirname(tree_path), exist_ok=True)
                content = f"{rel_path}\n{meta['size']} {meta['mtime']!r}\n"
                chunk_hashes = meta.get("chunk_hashes", [])
                content += "\n".join(chunk_hashes)
                if chunk_hashes:
                    content += "\n"
                self._write_gz(tree_path, content)
                self.file_count += 1
                self.inode_count += 1
        else:
            # Pack mode: only count files, no filesystem writes (no inodes)
            if entry_type != "dir":
                self.file_count += 1

        # Append to snap-index
        idx_meta = dict(meta)
        idx_meta["rel_path"] = rel_path
        self._snap_index_put(snap_name, rel_path,
                             self._build_index_entry(idx_meta))

    def set_entry_metadata(self, snap_name: str, rel_path: str, meta: dict) -> None:
        """Apply ownership, permissions, ACLs, and timestamps to an entry.

        For directories: applies to the tree/ dir, which is shared by all
        snapshots and therefore ends up with the metadata of the last backup.
        That is on purpose: it is what keeps the kernel from letting a user
        into an older snapshot of a directory he lost his permissions on. The
        metadata of *this* snapshot is in the index, see get_entry_full().
        For non-dirs: applies directly to the tree/ file, which is per
        snapshot.

        meta dict keys used here:
            type:           "dir" or one of the non-directory types
            mode:           int (file mode bits)
            uid, gid:       int
            atime, mtime:   float
            acl:            str or None

        The default ACL and the extended attributes are not applied: they
        live in the index, see write_entry() and _build_index_entry().
        """
        self.check_writable(snap_name)
        if self.mode == "pack":
            return
        self._safe_rel_path(rel_path)
        if meta.get("type") == "dir":
            tree_dir_path = os.path.join(str(self.tree_dir), rel_path) if rel_path != "." else str(self.tree_dir)
            self._ensure_in_tree(tree_dir_path)
            targets = [tree_dir_path]
        else:
            tree_path = self._tree_entry_path(rel_path, snap_name)
            self._ensure_in_tree(tree_path)
            targets = [tree_path]

        # Never honour setuid/setgid/sticky bits from the client — backupd
        # runs as root, and letting the client set S_ISUID on a restored
        # file would give an unprivileged mounter an arbitrary root-owned
        # setuid binary. Strip 07000 unconditionally.
        safe_mode = stat.S_IMODE(meta["mode"]) & 0o0777

        for target in targets:
            try:
                os.chown(target, meta["uid"], meta["gid"])
            except (PermissionError, OSError) as exc:
                logger.debug("chown %s: %s", target, exc)

            # Start from a clean slate. An entry in tree/ can already carry an
            # ACL: a directory is shared by all snapshots and keeps whatever
            # the last backup put on it, and anything we create inherits an
            # ACL from a default ACL further up in the repository. Setting an
            # ACL replaces the old one, but not setting any would leave it --
            # and chmod only recalculates the mask, so a leftover named entry
            # becomes effective again as soon as the mode carries group
            # permissions.
            _remove_acl(target)
            if meta.get("type") == "dir":
                # The default ACL of this snapshot lives in the index. On the
                # directory it would only make everything we create below it
                # inherit an ACL, so we clear it and never set one.
                _remove_acl(target, default=True)

            try:
                os.chmod(target, safe_mode)
            except (PermissionError, OSError) as exc:
                logger.debug("chmod %s: %s", target, exc)
            if meta.get("acl"):
                _set_acl_text(target, meta["acl"])

            try:
                os.utime(target, (meta["atime"], meta["mtime"]))
            except (OSError, AttributeError):
                pass

    def set_dirs_metadata(self, snap_name: str, dir_entries: list) -> None:
        """Apply metadata for multiple directories in one call.

        dir_entries is a list of (rel_path, meta) tuples.
        Sorts deepest-first internally so tree/ directory mtimes
        are not clobbered by later operations.
        """
        self.check_writable(snap_name)
        if self.mode == "pack":
            return
        for rel_path, meta in sorted(dir_entries, key=lambda e: e[0], reverse=True):
            self.set_entry_metadata(snap_name, rel_path, meta)

    def entry_from_index(self, snap_name: str, rel_path: str) -> Optional[dict]:
        """Build the entry info from the snap-index. Returns None if absent."""
        parsed = self._snap_index_get_parsed(snap_name, rel_path)
        if parsed is None:
            return None
        result = {
            "mode": parsed["mode"],
            "uid": parsed["uid"],
            "gid": parsed["gid"],
            "mtime": parsed["mtime"],
            "acl": parsed.get("acl"),
            "default_acl": parsed.get("default_acl"),
            "xattrs": parsed.get("xattrs"),
        }
        if parsed["type"] == "file":
            result["type_line"] = f"{parsed['size']} {parsed['mtime']!r}"
            result["file_size"] = parsed["size"]
            result["file_mtime"] = parsed["mtime"]
            result["chunk_hashes"] = parsed.get("chunk_hashes", [])
        elif parsed["type"] == "dir":
            result["type_line"] = "DIR"
        else:
            result["type_line"] = parsed["type"].upper()
        return result

    def get_entry_full(self, snap_name: str, rel_path: str) -> Optional[dict]:
        """Read all info for an entry in one shot.

        Non-directories carry their metadata in their tree/ entry, which is
        per snapshot, so that is one lstat plus one ACL read plus the file.
        A directory in tree/ is shared by all snapshots and thus carries the
        metadata of the last backup, so its metadata comes from the index --
        one lookup, no filesystem access.

        Returns a dict with mode, uid, gid, mtime, acl, default_acl, xattrs
        and, for regular files, file_size, file_mtime, chunk_hashes.  Returns
        None if the entry is not part of this snapshot.
        """
        if self.mode == "pack":
            # Pack mode: O(1) index lookup
            return self.entry_from_index(snap_name, rel_path)

        tree_path = self._tree_entry_path(rel_path, snap_name)
        if not os.path.lexists(tree_path):
            # A directory, or not part of this snapshot.
            return self.entry_from_index(snap_name, rel_path)
        entry_path = tree_path
        try:
            st = os.lstat(entry_path)
        except OSError:
            return None
        if not stat.S_ISREG(st.st_mode):
            return None
        acl = _get_acl_text(entry_path)
        result = {
            "mode": st.st_mode,
            "uid": st.st_uid,
            "gid": st.st_gid,
            "mtime": st.st_mtime,
            "acl": acl,
            "default_acl": None,
        }
        lines = self._read_gz(entry_path).strip().split("\n")
        if len(lines) >= 2:
            type_line = lines[1]
            result["type_line"] = type_line
            if type_line and type_line[0].isdigit():
                header = type_line.split()
                result["file_size"] = int(header[0])
                result["file_mtime"] = float(header[1]) if len(header) > 1 else st.st_mtime
                result["chunk_hashes"] = [h for h in lines[2:] if h] if len(lines) > 2 else []
        return result

    _FALLBACK_ENTRY = _SNAP_HEADER.pack(0, 0, 0, 0, 0, 0.0, 0.0, 0.0) + struct.pack('>HH', 3, 0) + struct.pack('>HB', 0, 0)

    def link_entry(self, from_snap: str, to_snap: str, rel_path: str,
                   is_dir: bool = None, index_val: bytes = None,
                   meta: dict = None) -> bool:
        """Link an entry from one snapshot to another (for unchanged entries).

        For directories: ensures the tree/ dir exists; there is nothing to
        link, their metadata is in the index.
        For non-dirs: hardlinks the tree/ file.
        Returns True on success, False if source doesn't exist.

        index_val:  raw binary index value to copy into the new snapshot's index.
        meta:       dict to build index entry from (used when metadata changed).
        If neither is given, a minimal fallback entry is written.
        """
        # Only where it goes. Where it comes from is somebody else's
        # finished snapshot -- that is the whole point of linking.
        self.check_writable(to_snap)
        self._safe_rel_path(rel_path)
        if self.mode == "pack":
            # Pack mode: no hardlinks, only write index entry
            self.file_count += 1
            if index_val is not None:
                val = index_val
            elif meta is not None:
                idx_meta = dict(meta)
                idx_meta["rel_path"] = rel_path
                val = self._build_index_entry(idx_meta)
            else:
                val = self._FALLBACK_ENTRY
            self._snap_index_put(to_snap, rel_path, val)
            return True

        if is_dir is None:
            # Determine type from index_val if available
            if index_val:
                parsed = self._parse_index_entry(index_val)
                is_dir = parsed is not None and parsed["type"] == "dir"
            else:
                # Fall back to checking tree/ path
                src_tree = self._tree_entry_path(rel_path, from_snap)
                is_dir = not os.path.lexists(src_tree)

        if is_dir:
            # Ensure tree/ directory exists (shared across snapshots). There
            # is nothing to link: the metadata of a directory is in the index.
            tree_dir_path = os.path.join(str(self.tree_dir), rel_path) if rel_path != "." else str(self.tree_dir)
            self._ensure_in_tree(tree_dir_path)
            os.makedirs(tree_dir_path, exist_ok=True)
        else:
            # Hardlink tree/ entry: old snap → new snap
            src_tree = self._tree_entry_path(rel_path, from_snap)
            dst_tree = self._tree_entry_path(rel_path, to_snap)
            self._ensure_in_tree(src_tree)
            self._ensure_in_tree(dst_tree)
            if not os.path.lexists(src_tree):
                return False
            os.makedirs(os.path.dirname(dst_tree), exist_ok=True)
            os.link(src_tree, dst_tree)

        self.file_count += 1

        # Append to snap-index
        if index_val is not None:
            val = index_val
        elif meta is not None:
            idx_meta = dict(meta)
            idx_meta["rel_path"] = rel_path
            val = self._build_index_entry(idx_meta)
        else:
            val = self._FALLBACK_ENTRY
        self._snap_index_put(to_snap, rel_path, val)

        return True


    def link_unchanged_entries(self, from_snap: str, to_snap: str,
                              entries: list) -> int:
        """Server-side batch fast path: link multiple unchanged entries at once.

        entries is a list of (rel_path, is_dir) tuples.

        For each entry:
        - Adds the new snapshot's snap_id to the existing entry in the shared index
        - For tree mode: hardlinks the tree/ file of a non-directory, and
          makes sure the tree/ directory of a directory exists

        Returns the number of successfully linked entries.
        """
        # Only where they go, see link_entry().
        self.check_writable(to_snap)
        linked = 0

        if self.mode == "pack":
            for rel_path, is_dir in entries:
                self.file_count += 1
                self._snap_index_link(to_snap, rel_path, from_snap=from_snap)
                linked += 1
        else:
            for rel_path, is_dir in entries:
                self._safe_rel_path(rel_path)
                if is_dir:
                    tree_dir_path = os.path.join(str(self.tree_dir), rel_path) if rel_path != "." else str(self.tree_dir)
                    self._ensure_in_tree(tree_dir_path)
                    os.makedirs(tree_dir_path, exist_ok=True)
                else:
                    src_tree = self._tree_entry_path(rel_path, from_snap)
                    dst_tree = self._tree_entry_path(rel_path, to_snap)
                    self._ensure_in_tree(src_tree)
                    self._ensure_in_tree(dst_tree)
                    if not os.path.lexists(src_tree):
                        continue
                    os.makedirs(os.path.dirname(dst_tree), exist_ok=True)
                    os.link(src_tree, dst_tree)

                self.file_count += 1
                self._snap_index_link(to_snap, rel_path, from_snap=from_snap)
                linked += 1

        return linked


    def _parse_entry(self, snap_name, rel_path, val, filter_path, full):
        """Parse a binary index value into an entry dict. Returns None on parse error."""
        parsed = self._parse_index_entry(val)
        if parsed is None:
            return None

        entry = {
            "rel_path": rel_path,
            "type": parsed["type"],
            "mode": parsed["mode"],
            "uid": parsed["uid"],
            "gid": parsed["gid"],
            "size": parsed["size"],
            "mtime": parsed["mtime"],
            "symlink_target": parsed.get("symlink_target"),
            "link_target": parsed.get("link_target"),
        }
        if "devmajor" in parsed:
            entry["devmajor"] = parsed["devmajor"]
            entry["devminor"] = parsed["devminor"]

        if full:
            # A directory has no per snapshot entry on disk, so everything
            # about it comes from the index. For the rest the tree/ entry is
            # the source: its ACL is a real ACL there, and only it knows the
            # chunk hashes.
            entry["atime"] = parsed.get("atime", 0.0)
            entry["acl"] = parsed.get("acl")
            entry["default_acl"] = parsed.get("default_acl")
            entry["xattrs"] = parsed.get("xattrs")
            entry["chunk_hashes"] = []
            if parsed["type"] == "file":
                entry["chunk_hashes"] = parsed.get("chunk_hashes", [])
            if self.get_mode() != "pack" and parsed["type"] != "dir":
                entry_path = self._tree_entry_path(rel_path, snap_name)
                st = os.lstat(entry_path)
                entry["atime"] = st.st_atime
                entry["acl"] = _get_acl_text(entry_path)
                if parsed["type"] == "file":
                    lines = self._read_gz(entry_path).strip().split("\n")
                    entry["chunk_hashes"] = [h for h in lines[2:] if h] if len(lines) > 2 else []

        return entry

    # -- cursor-based entry iteration (session kept open) --

    def open_entry_cursor(self, snap_name: str, filter_path: Optional[str] = None,
                          full: bool = False) -> None:
        """Open a cursor for iterating over snapshot entries.

        The cursor stays open until close_entry_cursor() is called.
        Use next_entries(count) to read chunks.
        """
        self.close_entry_cursor()
        if filter_path is not None:
            filter_path = filter_path.strip("/")

        # Open DB first so _resolve_snap_id can use it. We only read here, so
        # a read-only connection does: that is what a restore mount has.
        db = self._snap_db
        if db is None:
            db = self._open_snap_db(readonly=True)
        if db is None:
            raise FileNotFoundError(f"Snapshot not found: {snap_name}")

        snap_id = self._resolve_snap_id(snap_name)
        if snap_id == 0:
            raise FileNotFoundError(f"Snapshot not found: {snap_name}")

        # A real SQLite cursor: the rows are read as they are needed instead
        # of building the whole result of a snapshot in memory first.
        if filter_path is not None:
            cursor = db.execute(self._SNAP_ITER_FILTER_SQL,
                                (snap_id,
                                filter_path,
                                filter_path + "/",
                                filter_path + "/\xff\xff\xff\xff"))
        else:
            cursor = db.execute(self._SNAP_ITER_SQL, (snap_id,))
        self._entry_cursor_results = self._iter_latest_per_key(cursor)

        self._entry_cursor_cur = cursor
        self._entry_cursor_snap = snap_name
        self._entry_cursor_snap_id = snap_id
        self._entry_cursor_filter = filter_path
        self._entry_cursor_full = full

    def next_entries(self, count: int = 10000) -> list:
        """Read the next `count` entries from the open cursor.

        Returns an empty list when exhausted.
        """
        if self._entry_cursor_cur is None:
            return []

        snap_name = self._entry_cursor_snap
        full = self._entry_cursor_full
        snap_id = self._entry_cursor_snap_id
        filter_path = self._entry_cursor_filter
        entries = []

        for rel_path, entry_data in self._entry_cursor_results:
            entry = self._parse_entry(snap_name, rel_path, entry_data, filter_path, full)
            if entry is not None:
                entries.append(entry)
            if len(entries) >= count:
                break

        if not entries:
            self.close_entry_cursor()

        return entries

    def close_entry_cursor(self) -> None:
        """Close the entry cursor."""
        if getattr(self, '_entry_cursor_cur', None) is not None:
            try:
                self._entry_cursor_cur.close()
            except sqlite3.Error:
                pass
            self._entry_cursor_cur = None
        self._entry_cursor_results = None
        self._entry_cursor_snap = None
        self._entry_cursor_snap_id = None
        self._entry_cursor_filter = None
        self._entry_cursor_full = None

    def iter_entries(self, snap_name: str, filter_path: Optional[str] = None,
                     full: bool = False):
        """Yield entry dicts one by one. For local use (no protocol)."""
        self.open_entry_cursor(snap_name, filter_path, full)
        try:
            while True:
                batch = self.next_entries(10000)
                if not batch:
                    break
                yield from batch
        finally:
            self.close_entry_cursor()

    def list_snapshots(self) -> list:
        """Return list of snapshot info dicts."""
        if not self.snapshots_dir.exists():
            return []

        result = []
        for snap in sorted(p for p in self.snapshots_dir.iterdir() if p.is_dir()):
            ts = datetime.fromtimestamp(snap.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            complete = self.is_complete(snap.name)
            running = self.is_running(snap.name)
            running_since = None
            if running:
                pidfile = snap / "running"
                try:
                    running_since = datetime.fromtimestamp(
                        pidfile.stat().st_ctime).strftime("%Y-%m-%d %H:%M:%S")
                except OSError:
                    pass

            # Read stats from complete file if available.
            stats = self.read_complete_stats(snap.name)
            file_count = stats.get("files", 0)
            inode_count = stats.get("inodes", 0)
            start_time = stats.get("start_time", "")
            end_time = stats.get("end_time", "")

            # Calculate duration from start_time and end_time.
            duration = ""
            if start_time and end_time:
                try:
                    fmt = "%Y-%m-%d %H:%M:%S"
                    dt_start = datetime.strptime(start_time, fmt)
                    dt_end = datetime.strptime(end_time, fmt)
                    elapsed = int((dt_end - dt_start).total_seconds())
                    if elapsed < 0:
                        elapsed = 0
                    hours, rem = divmod(elapsed, 3600)
                    minutes, seconds = divmod(rem, 60)
                    if hours:
                        duration = f"{hours}h {minutes:02d}m {seconds:02d}s"
                    elif minutes:
                        duration = f"{minutes}m {seconds:02d}s"
                    else:
                        duration = f"{seconds}s"
                except (ValueError, TypeError):
                    pass

            total_bytes = stats.get("total_bytes", 0)
            stored_bytes = stats.get("stored_bytes", 0)

            result.append({
                "name": snap.name,
                "files": file_count,
                "inodes": inode_count,
                "created": ts,
                "start_time": start_time,
                "end_time": end_time,
                "duration": duration,
                "total_bytes": total_bytes,
                "stored_bytes": stored_bytes,
                "complete": complete,
                "running": running,
                "running_since": running_since,
            })
        return result

    def _remove_snapshot(self, snap_name: str) -> None:
        """Remove a snapshot's tree/ entries, snap directory, and snap-index entries."""
        snap_dir = self.snap_dir(snap_name)
        if not snap_dir.exists():
            raise FileNotFoundError(f"Snapshot not found: {snap_name}")

        # Remove tree/ entries for non-dir entries using the index
        if self.mode != "pack":
            for rel_path, val in self._iter_snap_index(snap_name):
                parsed = self._parse_index_entry(val)
                if parsed is None or parsed["type"] == "dir":
                    continue
                tree_path = self._tree_entry_path(rel_path, snap_name)
                try:
                    os.unlink(tree_path)
                except OSError:
                    pass
                parent = os.path.dirname(tree_path)
                while parent != str(self.tree_dir):
                    try:
                        os.rmdir(parent)
                    except OSError:
                        break
                    parent = os.path.dirname(parent)

        # Remove snap_id from shared snap-index
        self._remove_snap_from_index(snap_name)

        # Remove snapshot directory (complete + running + chunks)
        shutil.rmtree(snap_dir)

    def _remove_snap_from_index(self, snap_name: str) -> None:
        """Remove a snapshot from the snap-index."""
        db_path = self._snap_index_db_path()
        if not os.path.exists(db_path):
            self._snap_id_cache.pop(snap_name, None)
            return
        snap_id = self._resolve_snap_id(snap_name)
        db = sqlite3.connect(db_path)
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=NORMAL")
        try:
            if snap_id != 0:
                db.execute("DELETE FROM snap_entries WHERE snap_id=?", (snap_id,))
                # Whatever no other snapshot references any more.
                db.execute("DELETE FROM entries WHERE NOT EXISTS "
                        "(SELECT 1 FROM snap_entries se WHERE se.entry_id = entries.entry_id)")
            db.execute("DELETE FROM snap_meta WHERE snap_name=?", (snap_name,))
            db.commit()
        finally:
            db.close()

        self._snap_id_cache.pop(snap_name, None)

    def delete_snapshot(self, snap_name: str) -> int:
        """Delete a snapshot and run GC.  Returns number of orphaned blocks removed."""
        self.lock_repo()
        self.load_pack_index()
        try:
            return self._delete_snapshot_locked(snap_name)
        finally:
            self.unlock_repo()

    def _build_live_bloom(self, exclude_set: set = None):
        """Build a Bloom filter containing all chunk IDs from live snapshots.

        Returns a Bloom filter, or None if there are no live snapshots.
        Uses pack-index entry count as size estimate for the filter.
        """
        from rbloom import Bloom
        if not self.snapshots_dir.exists():
            return None
        excl = exclude_set or set()
        snaps = [s.name for s in self.snapshots_dir.iterdir()
                 if s.is_dir() and s.name not in excl]
        if not snaps:
            return None
        # Use pack-index entry count as upper bound for bloom filter size
        row = self._pack_db.execute("SELECT COUNT(*) FROM pack_index").fetchone()
        num_entries = row[0] if row[0] > 0 else 1
        bloom = Bloom(num_entries, 0.01)
        for snap in snaps:
            for h in self.iter_chunks_file(snap):
                bloom.add(h)
        return bloom

    def _delete_snapshot_locked(self, snap_name: str) -> int:
        """Internal delete — caller must hold the lock."""
        logger.info("Deleting snapshot '%s' ...", snap_name)
        chunks_path = self.snap_chunks_path(snap_name)
        has_chunks = chunks_path.exists()
        # Build Bloom filter of live hashes from all OTHER snapshots
        bloom = self._build_live_bloom(exclude_set={snap_name})

        # Find orphaned hashes: in dead snapshot but not in any live snapshot
        orphaned = set()
        if has_chunks:
            if bloom is not None:
                for h in self.iter_chunks_file(snap_name):
                    if h not in bloom:
                        orphaned.add(h)
            else:
                # No other snapshots — all hashes are orphaned
                for h in self.iter_chunks_file(snap_name):
                    orphaned.add(h)

        self._remove_snapshot(snap_name)

        if not orphaned:
            logger.info("GC done: 0 orphaned blocks removed")
            return 0

        self._gc_remove_from_index(orphaned)
        logger.info("GC done: %d orphaned blocks removed. "
                    "Run 'repack' to reclaim disk space.", len(orphaned))
        return len(orphaned)

    @staticmethod
    def _parse_snap_date(name: str):
        """Try to extract a datetime from a snapshot name.

        Supports formats like:
          2026-03-06T12:30:00   (ISO)
          2026-03-06_12-30-00   (default backup naming)
          2026-03-06_12-30      (no seconds)
          2026-03-06            (date only)
        Returns datetime or None.
        """
        import re
        # Normalize: replace underscores with T, dashes in time part with colons
        # Try progressively shorter formats
        s = name.strip()
        for fmt in ("%Y-%m-%dT%H:%M:%S",
                     "%Y-%m-%dT%H-%M-%S",
                     "%Y-%m-%d_%H-%M-%S",
                     "%Y-%m-%d_%H-%M",
                     "%Y-%m-%dT%H:%M",
                     "%Y-%m-%d"):
            try:
                return datetime.strptime(s, fmt)
            except ValueError:
                continue
        # Try matching a date prefix (name might have extra suffix)
        m = re.match(r"(\d{4}-\d{2}-\d{2})", s)
        if m:
            try:
                return datetime.strptime(m.group(1), "%Y-%m-%d")
            except ValueError:
                pass
        return None

    def _read_retention_file(self, name: str) -> int:
        """Read a retention value from a file in the repository root.

        Returns the integer value from the file, or 0 if the file
        does not exist or cannot be parsed.
        """
        path = self.root / name
        if not path.exists():
            return 0
        try:
            return int(path.read_text().strip())
        except (ValueError, OSError):
            return 0

    def apply_retention(self, daily: int = None, weekly: int = None,
                        monthly: int = None, dry_run: bool = False) -> list:
        """Delete snapshots that fall outside the retention policy.

        Keeps the *newest* snapshot per calendar day / ISO week / month,
        then retains at most ``daily`` daily, ``weekly`` weekly, and
        ``monthly`` monthly snapshots.  Any snapshot not covered by at
        least one retention bucket is deleted.

        If daily/weekly/monthly are not passed (None), values are read
        from .daily/.weekly/.monthly files in the repository root.
        A missing file means 0 (no retention limit for that bucket).

        Returns the list of deleted snapshot names.
        """
        if daily is None:
            daily = self._read_retention_file(".daily")
        if weekly is None:
            weekly = self._read_retention_file(".weekly")
        if monthly is None:
            monthly = self._read_retention_file(".monthly")
        self.lock_repo()
        self.load_pack_index()
        try:
            return self._apply_retention_locked(daily, weekly, monthly, dry_run)
        finally:
            self.unlock_repo()

    def _apply_retention_locked(self, daily, weekly, monthly, dry_run):
        snaps = self.list_snapshots()
        if not snaps:
            return []

        # If no retention configured at all, nothing to do.
        if not daily and not weekly and not monthly:
            return []

        # Build (name, datetime) pairs sorted newest-first.
        entries = []
        for s in snaps:
            name = s["name"]
            if not s["complete"]:
                # A backup that broke off half way. Counting it would let
                # it take the slot of the day and push out a snapshot
                # somebody could actually restore from -- and deleting it
                # here is not this method's business either. It is left
                # alone in both directions.
                logger.warning("Ignoring incomplete snapshot: %s", name)
                continue
            dt = self._parse_snap_date(name)
            if dt is None:
                logger.warning("Cannot parse date from snapshot name '%s', keeping it", name)
                continue
            entries.append((name, dt))
        entries.sort(key=lambda e: e[1], reverse=True)

        # Retention cascade: daily → weekly → monthly.
        #
        # - daily=N:   keep ALL snapshots from the N most recent days
        # - weekly=M:  for snapshots older than the daily window, keep
        #              the NEWEST snapshot per calendar week, M weeks back
        # - monthly=L: for snapshots older than daily+weekly, keep
        #              the NEWEST snapshot per month, L months back

        keep = set()

        # Group by day
        day_groups = {}
        for name, dt in entries:
            k = dt.date()
            if k not in day_groups:
                day_groups[k] = []
            day_groups[k].append(name)

        # Daily: keep all snapshots from the N newest days
        daily_days = list(day_groups.keys())[:daily] if daily > 0 else []
        daily_cutoff = set()
        for k in daily_days:
            keep.update(day_groups[k])
            daily_cutoff.update(day_groups[k])

        # Weekly: from snapshots NOT covered by daily, keep newest per week
        weekly_kept_weeks = set()
        if weekly > 0:
            week_groups = {}
            for name, dt in entries:
                if name in daily_cutoff:
                    continue
                k = dt.isocalendar()[:2]
                if k not in week_groups:
                    week_groups[k] = name  # newest (entries are newest-first)
            kept_weeks = list(week_groups.keys())[:weekly]
            weekly_kept_weeks = set(kept_weeks)
            for k in kept_weeks:
                keep.add(week_groups[k])

        # Monthly: from snapshots outside daily days AND outside weekly weeks,
        # keep newest per month
        if monthly > 0:
            daily_days_set = set(daily_days)
            month_groups = {}
            for name, dt in entries:
                # Skip snapshots from days covered by daily
                if dt.date() in daily_days_set:
                    continue
                # Skip snapshots from weeks covered by weekly
                if dt.isocalendar()[:2] in weekly_kept_weeks:
                    continue
                k = (dt.year, dt.month)
                if k not in month_groups:
                    month_groups[k] = name
            kept_months = list(month_groups.keys())[:monthly]
            for k in kept_months:
                keep.add(month_groups[k])

        deleted = []
        to_delete = []
        for name, _ in entries:
            if name not in keep:
                if dry_run:
                    logger.info("Retention: would delete snapshot '%s'", name)
                    deleted.append(name)
                else:
                    to_delete.append(name)

        if to_delete:
            # Build Bloom filter from snapshots we're keeping
            exclude_set = set(to_delete)
            bloom = self._build_live_bloom(exclude_set)
            # Stream dead hashes and find orphaned
            orphaned = set()
            for name in to_delete:
                logger.info("Retention: deleting snapshot '%s'", name)
                for h in self.iter_chunks_file(name):
                    if bloom is None or h not in bloom:
                        orphaned.add(h)
                self._remove_snapshot(name)
                deleted.append(name)
            if orphaned:
                self._gc_remove_from_index(orphaned)
                logger.info("Retention GC: %d orphaned blocks removed.",
                            len(orphaned))
                saved = self._repack_locked()
                if saved:
                    logger.info("Repack: reclaimed %d bytes.", saved)

        return deleted

    def gc_orphaned_blocks(self) -> int:
        """Remove blocks from pack index not referenced by any snapshot.

        Fully empty pack files are deleted; partially empty packs
        keep their dead space until repack is run.
        """
        self.lock_repo()
        self.load_pack_index()
        try:
            return self._gc_orphaned_blocks_locked()
        finally:
            self.unlock_repo()

    def _gc_orphaned_blocks_locked(self) -> int:
        # Build Bloom filter of all live hashes
        bloom = self._build_live_bloom(set())
        # Scan pack index, find hashes not in live set
        orphaned = set()
        for row in self._pack_db.execute("SELECT hash FROM pack_index"):
            h = row[0]
            if bloom is None or h not in bloom:
                orphaned.add(h)

        if not orphaned:
            return 0

        self._gc_remove_from_index(orphaned)
        return len(orphaned)

    def _gc_remove_from_index(self, orphaned: set) -> None:
        """Remove orphaned hashes from pack index, delete fully empty packs."""
        # Build pack -> hashes mapping
        pack_hashes = {}
        for h, pid in self._pack_db.execute("SELECT hash, pack_id FROM pack_index"):
            pack_hashes.setdefault(pid, set()).add(h)

        # Delete orphaned entries
        self._pack_db.executemany(
            "DELETE FROM pack_index WHERE hash=?",
            [(h,) for h in orphaned])

        # Update commit marker
        surviving_pids = set()
        for pid, hashes in pack_hashes.items():
            if not hashes.issubset(orphaned):
                surviving_pids.add(pid)

        if not surviving_pids:
            self._pack_db.execute("DELETE FROM pack_meta WHERE key='last_commit'")
        else:
            max_pid = max(surviving_pids)
            pack_path = self._pack_path(max_pid)
            pack_size = pack_path.stat().st_size if pack_path.exists() else 0
            self._pack_db.execute(
                "INSERT OR REPLACE INTO pack_meta (key, value) VALUES (?, ?)",
                ('last_commit', struct.pack('>IQ', max_pid, pack_size)))

        self._pack_db.commit()

        # Delete fully empty pack files + empty bucket dirs
        for pid, hashes in pack_hashes.items():
            if hashes.issubset(orphaned):
                p = self._pack_path(pid)
                p.unlink(missing_ok=True)
                try:
                    p.parent.rmdir()
                except OSError:
                    pass

    def compact(self) -> dict:
        """Compact databases to reclaim disk space. Returns bytes saved per DB."""
        self.lock_repo()
        try:
            return self._compact_locked()
        finally:
            self.unlock_repo()

    def _compact_locked(self) -> dict:
        """Compact SQLite databases to reclaim disk space."""
        result = {}
        for name, path in [('snap_index', self._snap_index_db_path()),
                           ('pack_index', self._pack_index_path())]:
            if os.path.exists(path):
                # Close active connection if it's the pack db
                if name == 'pack_index' and self._pack_db is not None:
                    self._pack_db.commit()
                    self._pack_db.close()
                    self._pack_db = None
                old_size = os.path.getsize(path)
                db = sqlite3.connect(path)
                try:
                    db.execute("VACUUM")
                finally:
                    db.close()
                new_size = os.path.getsize(path)
                result[name] = old_size - new_size
                # Reopen pack db if we closed it
                if name == 'pack_index':
                    self._open_pack_db()
        return result

    def repair(self) -> dict:
        """Repair snap-index: remove orphaned entries not referenced by any snapshot.

        Returns dict with count of removed orphans.
        """
        self.lock_repo()
        try:
            return self._repair_locked()
        finally:
            self.unlock_repo()

    def _repair_locked(self) -> dict:
        db_path = self._snap_index_db_path()
        if not os.path.exists(db_path):
            return {"orphans": 0}
        # Remove entries no snapshot references any more, and membership rows
        # whose snapshot or entry is gone.
        db = sqlite3.connect(db_path)
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=NORMAL")
        try:
            total = db.execute("SELECT COUNT(*) FROM entries").fetchone()[0]
            db.execute("DELETE FROM snap_entries WHERE snap_id NOT IN "
                    "(SELECT snap_id FROM snap_meta)")
            db.execute("DELETE FROM snap_entries WHERE NOT EXISTS "
                    "(SELECT 1 FROM entries e WHERE e.entry_id = snap_entries.entry_id)")
            cur = db.execute("DELETE FROM entries WHERE NOT EXISTS "
                    "(SELECT 1 FROM snap_entries se WHERE se.entry_id = entries.entry_id)")
            orphans = cur.rowcount
            db.commit()
            logger.info("Repair: %d orphaned entries removed (of %d total)",
                        orphans, total)
            return {"orphans": orphans}
        finally:
            db.close()

    def repack(self) -> int:
        """Rewrite partially-dead packs to reclaim space. Returns bytes saved."""
        self.lock_repo()
        self.load_pack_index()
        try:
            return self._repack_locked()
        finally:
            self.unlock_repo()

    def _repack_locked(self) -> int:
        """Rewrite packs that contain dead entries."""
        live_by_pack = {}
        for h, pid, offset, length in self._pack_db.execute(
                "SELECT hash, pack_id, offset, length FROM pack_index"):
            live_by_pack.setdefault(pid, []).append((h, offset, length))

        saved = 0
        updates = []  # (h, pid, new_offset, length)
        for pid, entries in live_by_pack.items():
            pack_path = self._pack_path(pid)
            if not pack_path.exists():
                continue
            pack_size = pack_path.stat().st_size
            live_size = sum(64 + 4 + length for _, _, length in entries)
            if live_size >= pack_size:
                continue  # no dead space

            # Rewrite pack with only live entries
            tmp_path = pack_path.with_suffix('.tmp')
            with open(pack_path, 'rb') as src, open(tmp_path, 'wb') as dst:
                new_offset = 0
                for h, offset, length in sorted(entries, key=lambda e: e[1]):
                    src.seek(offset)
                    entry_data = src.read(64 + 4 + length)
                    dst.write(entry_data)
                    updates.append((h, pid, new_offset, length))
                    new_offset += 64 + 4 + length
            tmp_path.rename(pack_path)
            saved += pack_size - new_offset

        if updates:
            max_pid = max(live_by_pack.keys())
            pack_path = self._pack_path(max_pid)
            pack_size = pack_path.stat().st_size if pack_path.exists() else 0
            self._pack_db.executemany(
                "UPDATE pack_index SET offset=?, length=? WHERE hash=?",
                [(offset, length, h) for h, pid, offset, length in updates])
            self._pack_db.execute(
                "INSERT OR REPLACE INTO pack_meta (key, value) VALUES (?, ?)",
                ('last_commit', struct.pack('>IQ', max_pid, pack_size)))
            self._pack_db.commit()
        return saved

    def rebuild_pack_index(self) -> int:
        """Rebuild pack index by scanning all pack-*.dat files. Returns entry count."""
        self.lock_repo()
        self.load_pack_index()
        try:
            return self._rebuild_pack_index_locked()
        finally:
            self.unlock_repo()

    def _rebuild_pack_index_locked(self) -> int:
        # Clear existing index
        self._pack_db.execute("DELETE FROM pack_index")
        self._pack_db.execute("DELETE FROM pack_meta")

        if not self.packs_dir.exists():
            self._pack_db.commit()
            return 0

        count = 0
        last_pid = -1
        last_offset = 0
        for bucket_dir in sorted(self.packs_dir.iterdir()):
            if not bucket_dir.is_dir():
                continue
            for pack_file in sorted(bucket_dir.iterdir()):
                name = pack_file.name
                if not (name.startswith("pack-") and name.endswith(".dat")):
                    continue
                try:
                    pid = int(name[5:-4], 16)
                except ValueError:
                    continue
                file_size = pack_file.stat().st_size
                offset = 0
                with open(pack_file, 'rb') as f:
                    while offset + 68 <= file_size:
                        f.seek(offset)
                        header = f.read(68)
                        if len(header) < 68:
                            break
                        h = header[:64].decode('ascii', errors='replace')
                        blob_len = struct.unpack('>I', header[64:68])[0]
                        if offset + 68 + blob_len > file_size:
                            break
                        self._pack_db.execute(
                            "INSERT OR IGNORE INTO pack_index "
                            "(hash, pack_id, offset, length) VALUES (?, ?, ?, ?)",
                            (h, pid, offset, blob_len))
                        count += 1
                        offset += 68 + blob_len
                if pid > last_pid:
                    last_pid = pid
                    last_offset = offset

        if last_pid >= 0:
            self._pack_db.execute(
                "INSERT OR REPLACE INTO pack_meta (key, value) VALUES (?, ?)",
                ('last_commit', struct.pack('>IQ', last_pid, last_offset)))
        self._pack_db.commit()
        return count


# ---------------------------------------------------------------------------
# BackupClient — crypto + file I/O
# ---------------------------------------------------------------------------

class BackupClient:
    """Handles encryption/decryption and filesystem operations.

    Everything the repository holds goes through the server interface, and
    everything that needs the key happens here: the server sees no plaintext,
    no path and no chunk ID it could have computed itself.  The one thing the
    client does read directly is the snap-index of the previous snapshot --
    it downloads a copy to find out what changed, see _open_prev_index().
    """

    _CACHE_BASE = "/var/cache/otpme/backup"

    def __init__(self, server: object = None, password: str = None,
                 key: bytes = None, salt: bytes = None,
                 compress: bool = True):
        self.server = server
        self.compress = compress
        if key is not None:
            if len(key) != KEY_SIZE:
                raise ValueError(f"Key must be {KEY_SIZE} bytes, got {len(key)}")
            self.key = key
        elif password is not None:
            if salt is None:
                if server is None:
                    raise ValueError("Either server or salt must be provided")
                salt = server.get_salt()
            self.key = derive_key(password, salt)
        # Derive AES-SIV key for path encryption
        if hasattr(self, 'key'):
            self._path_key = _derive_path_key(self.key)
            self._siv = AESSIV(self._path_key)
            self._id_key = _derive_id_key(self.key)
        else:
            self._siv = None
            self._id_key = None
        self.logger = config.logger

    def encrypt_rel_path(self, rel_path: str) -> str:
        """Encrypt a relative path for storage on the server."""
        if self._siv is None or not rel_path or rel_path == '.':
            return rel_path
        return encrypt_path(self._siv, rel_path)

    def decrypt_rel_path(self, enc_path: str) -> str:
        """Decrypt an encrypted relative path from the server."""
        if self._siv is None or not enc_path or enc_path == '.':
            return enc_path
        return decrypt_path(self._siv, enc_path)

    def encrypt_symlink_target(self, target: str) -> str:
        """Encrypt a symlink target path using AES-SIV.

        Preserves leading '/' for absolute symlinks.
        """
        if self._siv is None or not target:
            return target
        absolute = target.startswith('/')
        enc = encrypt_path(self._siv, target.lstrip('/'))
        return ('/' + enc) if absolute else enc

    def decrypt_symlink_target(self, enc_target: str) -> str:
        """Decrypt an encrypted symlink target path.

        Falls back to returning the value as-is for legacy unencrypted targets.
        """
        if self._siv is None or not enc_target:
            return enc_target
        absolute = enc_target.startswith('/')
        try:
            dec = decrypt_path(self._siv, enc_target.lstrip('/'))
        except Exception:
            return enc_target
        return ('/' + dec) if absolute else dec

    def hash_block(self, plaintext: bytes) -> str:
        """Return the chunk ID of a plaintext block.

        Keyed, not a plain hash of the plaintext. The ID is the one thing
        about a chunk that the repository stores in the clear -- in the index,
        the chunks file, the pack index and the pack record header. A plain
        SHA-256 would let anybody with read access to the repository answer
        "is this particular file in this backup?": chunk the file the same
        way, hash it, look the ID up. With the repository key in the MAC that
        question can no longer be asked from outside.

        Deduplication is unaffected: it only ever worked within one
        repository, and a repository has one key.
        """
        return _hmac.new(self._id_key, plaintext, 'sha256').hexdigest()

    def encrypt_block(self, plaintext: bytes) -> bytes:
        """Compress (if enabled) and encrypt a plaintext block.  Returns flag+ciphertext."""
        if self.compress:
            compressed = zlib.compress(plaintext, COMPRESS_LEVEL)
            if len(compressed) < len(plaintext):
                return FLAG_ZLIB + encrypt_block(self.key, compressed)
        return FLAG_RAW + encrypt_block(self.key, plaintext)

    _KEY_CHECK_MAGIC = b"otpme-backup-key-check-v1"

    def _key_check_plaintext(self) -> bytes:
        """What the key check blob has to decrypt to.

        The salt is part of it, so the blob belongs to this repository and
        not merely to this key.
        """
        return self._KEY_CHECK_MAGIC + b"\n" + self.server.get_salt()

    def verify_key(self) -> None:
        """Make sure we hold the key this repository was written with.

        A wrong key does not fail on its own: every path is encrypted with
        it, so the whole tree looks new, nothing dedups, and the snapshots
        already there can no longer be read -- the repository would end up
        holding two sets of data nobody can use together.  So the repository
        keeps a blob encrypted with its key.  AES-GCM authenticates, which
        makes decrypting it at all the proof; we compare the plaintext too,
        to also catch a blob carried over from another repository.

        A repository that has none yet gets one, which is the case for a
        fresh one.  Raises OTPmeException on a mismatch.
        """
        wanted = self._key_check_plaintext()
        blob = self.server.get_key_check()
        if not blob:
            self.server.set_key_check(self.encrypt_block(wanted))
            return
        try:
            got = self.decrypt_block(blob)
        except Exception as e:
            msg = _("Wrong backup key for this repository.")
            raise OTPmeException(msg) from e
        if got != wanted:
            msg = _("Wrong backup key for this repository.")
            raise OTPmeException(msg)

    def decrypt_block(self, blob: bytes) -> bytes:
        """Decrypt and decompress an encrypted blob from the server."""
        flag, encrypted = blob[:1], blob[1:]
        data = decrypt_block(self.key, encrypted)
        if flag == FLAG_ZLIB:
            data = zlib.decompress(data)
        return data

    def _snap_index_cache_dir(self) -> str:
        """Return per-repo cache directory for the snap-index.

        Uses the salt as a stable repo identifier (unique per repo).
        Only one cached copy is kept (overwritten on each download).
        """
        salt = self.server.get_salt()
        repo_hash = hashlib.sha256(salt).hexdigest()[:16]
        cache_dir = os.path.join(self._CACHE_BASE, repo_hash)
        # Ensure .nobackup marker exists so the cache is excluded from backups
        nobackup = os.path.join(self._CACHE_BASE, ".nobackup")
        if not os.path.exists(nobackup):
            os.makedirs(self._CACHE_BASE, exist_ok=True)
            open(nobackup, 'a').close()
        return cache_dir

    def _open_prev_index(self, prev_snap: str) -> None:
        """Open access to the previous snapshot's index for lookups.

        For local servers: uses the server's snap-index SQLite directly.
        For remote servers: downloads compressed snap-index DB to local cache.
        """
        self._prev_snap = None
        self._prev_db = None
        if hasattr(self, '_prev_snap_id_cached'):
            del self._prev_snap_id_cached
        if prev_snap is None:
            return
        if isinstance(self.server, BackupServer):
            # Local: use server's snap-index directly
            self._prev_snap = prev_snap
            return
        # Remote: download compressed snap-index DB to cache
        idx_info = self.server.get_snap_index_info(prev_snap)
        total = idx_info['size']
        fingerprint = idx_info['fingerprint']
        if total == 0:
            return
        cache_dir = self._snap_index_cache_dir()
        os.makedirs(cache_dir, exist_ok=True)
        cached_db = os.path.join(cache_dir, "snap_index.db")
        fp_file = os.path.join(cache_dir, "fingerprint")
        # Check if cached copy is still current
        cached_fp = ''
        if os.path.exists(fp_file) and os.path.exists(cached_db):
            cached_fp = open(fp_file).read().strip()
        if cached_fp == fingerprint and os.path.getsize(cached_db) > 0:
            self.logger.info("Snap index cache is current, skipping download")
        else:
            chunk_size = 64 * 1024 * 1024  # 64 MiB
            offset = 0
            transferred = 0
            with open(cached_db, 'wb') as f:
                while offset < total:
                    compressed = self.server.get_snap_index_chunk(
                        prev_snap, offset, chunk_size)
                    if not compressed:
                        break
                    chunk = zlib.decompress(compressed)
                    f.write(chunk)
                    transferred += len(compressed)
                    offset += len(chunk)
            # Save fingerprint for next time
            with open(fp_file, 'w') as f:
                f.write(fingerprint + '\n')
            self.logger.info("Snap index downloaded (%d bytes, %d compressed)",
                        total, transferred)
        self._prev_db = sqlite3.connect(cached_db)
        self._prev_snap = prev_snap

    def _prev_index_get(self, rel_path: str) -> bytes:
        """Look up a path in the previous snapshot's index. Returns entry_data or None."""
        if self._prev_snap is None:
            return None
        if isinstance(self.server, BackupServer):
            # Local: direct lookup via server's snap-index
            return self.server._snap_index_get(self._prev_snap, rel_path)
        # Remote: lookup in the downloaded copy. It carries the snap_entries
        # table, so this is the same indexed query the server would run.
        if self._prev_db is None:
            return None
        snap_id = self._resolve_prev_snap_id()
        if snap_id == 0:
            return None
        row = self._prev_db.execute(BackupServer._SNAP_GET_SQL,
                                    (rel_path, snap_id)).fetchone()
        if row is None:
            return None
        return row[0]

    def _resolve_prev_snap_id(self) -> int:
        """Get snap_id for prev_snap from the local SQLite copy (remote case)."""
        if hasattr(self, '_prev_snap_id_cached'):
            return self._prev_snap_id_cached
        if self._prev_db is None:
            return 0
        row = self._prev_db.execute("SELECT snap_id FROM snap_meta WHERE snap_name=?",
                                     (self._prev_snap,)).fetchone()
        if row is None:
            return 0
        self._prev_snap_id_cached = row[0]
        return row[0]

    def _close_prev_index(self) -> None:
        """Close prev-index access. Cache is kept for next run."""
        if self._prev_db is not None:
            self._prev_db.close()
            self._prev_db = None
        self._prev_snap = None
        if hasattr(self, '_prev_snap_id_cached'):
            del self._prev_snap_id_cached

    def backup(self, source: str, name: Optional[str] = None,
               special_files: bool = False,
               excludes: Optional[list] = None,
               includes: Optional[list] = None,
               dry_run: bool = False) -> str:
        """Walk source directory, encrypt blocks, store via server.

        excludes: list of fnmatch patterns matched against the relative path.
        includes: list of fnmatch patterns that override excludes.
        dry_run:  if True, only log what would be backed up without storing anything.

        Refuses to run with the wrong key for the repository, see
        verify_key().
        """
        source = os.path.realpath(source)
        if not os.path.isdir(source):
            raise ValueError(f"Not a directory: {source}")

        snap_name = name or datetime.now().strftime("%Y-%m-%dT%H-%M-%S")

        if not dry_run:
            self.server.lock_repo()
        try:
            # Before anything is written: a wrong key would not fail on its
            # own, it would quietly fill the repository with data that does
            # not go with what is already there.
            self.verify_key()
            return self._backup_locked(source, snap_name, special_files,
                                        excludes, includes, dry_run)
        finally:
            if not dry_run:
                self.server.unlock_repo()

    def _backup_locked(self, source, snap_name, special_files, excludes,
                        includes, dry_run):
        if not dry_run:
            # Determine previous complete snapshot for change detection
            prev_snap = None
            snaps = self.server.list_snapshots()
            for s in reversed(snaps):
                if s["complete"]:
                    prev_snap = s["name"]
                    break

            # Fetch previous index for O(1) lookups
            self._open_prev_index(prev_snap)

            self.server.create_snapshot(snap_name)
            self.server.set_running(snap_name)

        repo_mode = self.server.get_mode()

        total_bytes = 0
        stored_bytes = 0
        file_count = 0
        dedup_blocks = 0
        new_blocks = 0
        skipped_files = 0
        unchanged_entries = []  # (rel_path, is_dir) for batch link
        _unchanged_flush_size = 10000

        # One pass over the tree creates the entries and stores the blocks,
        # applying the metadata of everything but a directory right away.
        # Directories come last, deepest-first, so that writing below them
        # does not clobber the mtime we just set.

        dir_entries = []  # (rel_path, meta) for deferred directory metadata pass
        seen_inodes = {}  # (dev, ino) -> rel_path for hardlink detection
        excluded_dirs = []  # relative prefixes of excluded directories
        included_dirs = []  # relative prefixes of included directories
        walk_skip_dirs = []  # absolute prefixes for _walk to skip scanning
        # Normalize patterns: strip trailing slashes
        if excludes:
            excludes = [pat.rstrip("/") for pat in excludes]
        if includes:
            includes = [pat.rstrip("/") for pat in includes]

        t_start = time.monotonic()

        if dry_run:
            self.logger.info("Dry run: %s", source)
        else:
            self.logger.info("Backing up %s → '%s'", source, snap_name)

        for fpath, st in _walk(source, excluded_dirs=walk_skip_dirs):
            rel = os.path.relpath(fpath, source)
            enc_rel = self.encrypt_rel_path(rel)
            if rel != ".":
                # Check if path is inside an included directory (subtree)
                in_included = any(rel.startswith(d) for d in included_dirs)
                # Check if path matches an include pattern directly
                pat_included = includes and any(
                    fnmatch.fnmatch(rel, pat) for pat in includes)
                included = in_included or pat_included
                if not included:
                    # Skip anything inside an already-excluded directory
                    if any(rel.startswith(d) for d in excluded_dirs):
                        continue
                    if excludes and any(fnmatch.fnmatch(rel, pat) for pat in excludes):
                        # Track excluded dirs so their entire subtree is skipped
                        if stat.S_ISDIR(st.st_mode):
                            excluded_dirs.append(rel + "/")
                            # Only skip scanning if no include pattern could
                            # match anything underneath this directory.
                            if not includes or not any(
                                    pat.startswith(rel + "/") for pat in includes):
                                walk_skip_dirs.append(fpath.rstrip("/") + "/")
                        continue
                # Track included directories so their subtree is also included
                if included and stat.S_ISDIR(st.st_mode):
                    included_dirs.append(rel + "/")
            mode = st.st_mode

            # Skip directories containing a .nobackup marker
            if stat.S_ISDIR(mode) and rel != ".":
                if os.path.exists(os.path.join(fpath, ".nobackup")):
                    excluded_dirs.append(rel + "/")
                    walk_skip_dirs.append(fpath.rstrip("/") + "/")
                    continue

            # Determine entry type for logging / dry_run
            entry_type = None
            if stat.S_ISDIR(mode):
                entry_type = "dir"
            elif stat.S_ISLNK(mode):
                entry_type = "symlink"
            elif stat.S_ISREG(mode):
                ino_key = (st.st_dev, st.st_ino)
                if st.st_nlink > 1 and ino_key in seen_inodes:
                    entry_type = "hardlink"
                else:
                    entry_type = "file"
            elif special_files and (stat.S_ISBLK(mode) or stat.S_ISCHR(mode)):
                entry_type = "blockdev" if stat.S_ISBLK(mode) else "chardev"
            elif special_files and stat.S_ISFIFO(mode):
                entry_type = "fifo"
            elif special_files and stat.S_ISSOCK(mode):
                entry_type = "socket"

            if entry_type is None:
                self.logger.debug("Skipping special file %s", fpath)
                continue

            if dry_run:
                msg = f"{entry_type}\t{rel}"
                print(msg)
                # Track hardlink inodes even in dry_run so detection works
                if entry_type == "file" and stat.S_ISREG(mode) and st.st_nlink > 1:
                    seen_inodes[(st.st_dev, st.st_ino)] = rel
                continue

            # Fast path: if ctime unchanged, nothing has changed at all
            prev_val = self._prev_index_get(enc_rel) if prev_snap else None
            if prev_val is not None:
                try:
                    prev_ctime = _entry_ctime(prev_val)
                except (struct.error, IndexError):
                    prev_ctime = None
            else:
                prev_ctime = None
            if prev_ctime is not None and prev_ctime == st.st_ctime:
                is_dir = (entry_type == "dir")
                if entry_type == "file":
                    if st.st_nlink > 1:
                        seen_inodes[ino_key] = enc_rel
                    file_count += 1
                    skipped_files += 1
                unchanged_entries.append((enc_rel, is_dir))
                if len(unchanged_entries) >= _unchanged_flush_size:
                    self.server.link_unchanged_entries(prev_snap, snap_name,
                                                       unchanged_entries)
                    unchanged_entries = []
                continue

            # Extended attributes are stored in pack mode only: that is what
            # a system backup uses, and a share does not serve them (see
            # OTPmeFsServer1.check_xattr()). Changing one changes the ctime,
            # so the fast path above does not hide it.
            entry_xattrs = None
            if repo_mode == "pack":
                entry_xattrs = _get_xattrs(fpath)

            try:
                if entry_type == "dir":
                    meta = {
                        "type": "dir",
                        "mode": mode,
                        "uid": st.st_uid, "gid": st.st_gid,
                        "atime": st.st_atime, "mtime": st.st_mtime,
                        "acl": _get_acl_text(fpath),
                        "default_acl": _get_default_acl_text(fpath),
                        "xattrs": entry_xattrs,
                        "ctime": st.st_ctime,
                    }
                    # Reuse the previous snapshot's index entry if unchanged
                    linked = False
                    if prev_snap:
                        prev = self.server.get_entry_full(prev_snap, enc_rel)
                        cur_acl = meta["acl"]
                        cur_default_acl = meta["default_acl"]
                        if (prev
                                and prev["uid"] == st.st_uid
                                and prev["gid"] == st.st_gid
                                and stat.S_IMODE(prev["mode"]) == stat.S_IMODE(mode)
                                and prev.get("mtime") == st.st_mtime
                                and prev["acl"] == cur_acl
                                and prev.get("default_acl") == cur_default_acl):
                            linked = self.server.link_entry(prev_snap, snap_name, enc_rel,
                                                            is_dir=True, meta=meta)
                    if not linked:
                        self.server.write_entry(snap_name, enc_rel, meta)
                    dir_entries.append((rel, enc_rel, meta))

                elif entry_type == "file":
                    if st.st_nlink > 1:
                        seen_inodes[ino_key] = enc_rel
                    file_count += 1
                    chunk_hashes = []

                    # mtime-based skip: reuse data entry + refs from previous snapshot
                    skipped = False
                    if prev_snap:
                        prev = self.server.get_entry_full(prev_snap, enc_rel)
                        if (prev and "file_size" in prev
                                and prev["file_mtime"] == st.st_mtime
                                and prev["file_size"] == st.st_size):
                            chunk_hashes = prev["chunk_hashes"]
                            # Link data entry if metadata unchanged, else write new
                            cur_acl = _get_acl_text(fpath)
                            if (prev["uid"] == st.st_uid
                                    and prev["gid"] == st.st_gid
                                    and stat.S_IMODE(prev["mode"]) == stat.S_IMODE(mode)
                                    and prev["acl"] == cur_acl):
                                self.server.link_entry(prev_snap, snap_name, enc_rel,
                                                        is_dir=False, meta={
                                                            "type": "file", "mode": mode,
                                                            "uid": st.st_uid, "gid": st.st_gid,
                                                            "size": st.st_size, "mtime": st.st_mtime,
                                                            "ctime": st.st_ctime,
                                                            "acl": cur_acl,
                                                            "xattrs": entry_xattrs,
                                                            "chunk_hashes": chunk_hashes,
                                                        })
                            else:
                                meta = {
                                    "type": "file",
                                    "mode": mode,
                                    "uid": st.st_uid, "gid": st.st_gid,
                                    "atime": st.st_atime, "mtime": st.st_mtime,
                                    "ctime": st.st_ctime,
                                    "acl": cur_acl,
                                    "xattrs": entry_xattrs,
                                    "size": st.st_size,
                                    "chunk_hashes": chunk_hashes,
                                }
                                self.server.write_entry(snap_name, enc_rel, meta)
                                if repo_mode != "pack":
                                    self.server.set_entry_metadata(snap_name, enc_rel, meta)
                            skipped_files += 1
                            skipped = True

                    if not skipped:
                        self.logger.info("Processing file: %s", fpath)
                        with open(fpath, "rb") as fh:
                            while True:
                                chunk = fh.read(CHUNK_SIZE)
                                if not chunk:
                                    break
                                total_bytes += len(chunk)
                                h = self.hash_block(chunk)
                                if self.server.block_exists(h):
                                    dedup_blocks += 1
                                else:
                                    blob = self.encrypt_block(chunk)
                                    self.server.store_block(h, blob)
                                    stored_bytes += len(chunk)
                                    new_blocks += 1
                                chunk_hashes.append(h)

                        # Check if file changed while we were reading it
                        try:
                            st2 = os.lstat(fpath)
                            if st2.st_mtime != st.st_mtime or st2.st_size != st.st_size:
                                self.logger.warning("File changed during backup: %s", fpath)
                        except OSError:
                            self.logger.warning("File vanished during backup: %s", fpath)

                        meta = {
                            "type": "file",
                            "mode": mode,
                            "uid": st.st_uid, "gid": st.st_gid,
                            "atime": st.st_atime, "mtime": st.st_mtime,
                            "ctime": st.st_ctime,
                            "acl": _get_acl_text(fpath),
                            "xattrs": entry_xattrs,
                            "size": st.st_size,
                            "chunk_hashes": chunk_hashes,
                        }
                        self.server.write_entry(snap_name, enc_rel, meta)
                        if repo_mode != "pack":
                            self.server.set_entry_metadata(snap_name, enc_rel, meta)

                elif entry_type == "symlink":
                    prev = self.server.get_entry_full(prev_snap, enc_rel) if prev_snap else None
                    meta = {
                        "type": "symlink",
                        "mode": mode,
                        "uid": st.st_uid, "gid": st.st_gid,
                        "atime": st.st_atime, "mtime": st.st_mtime,
                        "ctime": st.st_ctime,
                        "xattrs": entry_xattrs,
                        "symlink_target": self.encrypt_symlink_target(os.readlink(fpath)),
                    }
                    if (prev
                            and prev["uid"] == st.st_uid
                            and prev["gid"] == st.st_gid
                            and self.server.link_entry(prev_snap, snap_name, enc_rel,
                                                        is_dir=False, meta=meta)):
                        pass
                    else:
                        self.server.write_entry(snap_name, enc_rel, meta)
                        if repo_mode != "pack":
                            self.server.set_entry_metadata(snap_name, enc_rel, meta)

                elif entry_type == "hardlink":
                    prev = self.server.get_entry_full(prev_snap, enc_rel) if prev_snap else None
                    meta = {
                        "type": "hardlink",
                        "link_target": seen_inodes[ino_key],
                        "mode": mode,
                        "uid": st.st_uid, "gid": st.st_gid,
                        "atime": st.st_atime, "mtime": st.st_mtime,
                        "ctime": st.st_ctime,
                        "xattrs": entry_xattrs,
                    }
                    if (prev
                            and prev["uid"] == st.st_uid
                            and prev["gid"] == st.st_gid
                            and self.server.link_entry(prev_snap, snap_name, enc_rel,
                                                        is_dir=False, meta=meta)):
                        pass
                    else:
                        self.server.write_entry(snap_name, enc_rel, meta)
                        if repo_mode != "pack":
                            self.server.set_entry_metadata(snap_name, enc_rel, meta)
                    continue

                elif entry_type in ("blockdev", "chardev"):
                    prev = self.server.get_entry_full(prev_snap, enc_rel) if prev_snap else None
                    meta = {
                        "type": entry_type,
                        "mode": mode,
                        "uid": st.st_uid, "gid": st.st_gid,
                        "atime": st.st_atime, "mtime": st.st_mtime,
                        "ctime": st.st_ctime,
                        "xattrs": entry_xattrs,
                        "devmajor": os.major(st.st_rdev),
                        "devminor": os.minor(st.st_rdev),
                    }
                    if (prev
                            and prev["uid"] == st.st_uid
                            and prev["gid"] == st.st_gid
                            and stat.S_IMODE(prev["mode"]) == stat.S_IMODE(mode)
                            and self.server.link_entry(prev_snap, snap_name, enc_rel,
                                                        is_dir=False, meta=meta)):
                        pass
                    else:
                        self.server.write_entry(snap_name, enc_rel, meta)
                        if repo_mode != "pack":
                            self.server.set_entry_metadata(snap_name, enc_rel, meta)

                elif entry_type in ("fifo", "socket"):
                    prev = self.server.get_entry_full(prev_snap, enc_rel) if prev_snap else None
                    meta = {
                        "type": entry_type,
                        "mode": mode,
                        "uid": st.st_uid, "gid": st.st_gid,
                        "atime": st.st_atime, "mtime": st.st_mtime,
                        "ctime": st.st_ctime,
                        "xattrs": entry_xattrs,
                    }
                    if (prev
                            and prev["uid"] == st.st_uid
                            and prev["gid"] == st.st_gid
                            and stat.S_IMODE(prev["mode"]) == stat.S_IMODE(mode)
                            and self.server.link_entry(prev_snap, snap_name, enc_rel,
                                                        is_dir=False, meta=meta)):
                        pass
                    else:
                        self.server.write_entry(snap_name, enc_rel, meta)
                        if repo_mode != "pack":
                            self.server.set_entry_metadata(snap_name, enc_rel, meta)

            except (PermissionError, OSError) as exc:
                self.logger.warning("Skipping %s: %s", fpath, exc)

        if dry_run:
            self._close_prev_index()
            return snap_name

        # Flush remaining unchanged entries
        if unchanged_entries:
            self.server.link_unchanged_entries(prev_snap, snap_name,
                                               unchanged_entries)

        # Deferred: set directory metadata deepest-first so mtime isn't
        # clobbered by later file creation in tree/.
        if dir_entries and repo_mode != "pack":
            self.logger.info("Processing changed directories: %d", len(dir_entries))
            # dir_entries is (rel, enc_rel, meta); server needs (enc_rel, meta)
            enc_dir_entries = [(enc_r, m) for _, enc_r, m in dir_entries]
            self.server.set_dirs_metadata(snap_name, enc_dir_entries)

        total_mb  = total_bytes  / 1024 ** 2
        stored_mb = stored_bytes / 1024 ** 2
        saved_pct = (1 - stored_bytes / max(1, total_bytes)) * 100

        elapsed = time.monotonic() - t_start
        hours, rem = divmod(int(elapsed), 3600)
        minutes, seconds = divmod(rem, 60)
        if hours:
            duration = f"{hours}h {minutes:02d}m {seconds:02d}s"
        elif minutes:
            duration = f"{minutes}m {seconds:02d}s"
        else:
            duration = f"{elapsed:.1f}s"

        log_lines = []
        log_msg = _("Done: {file_count} files, {skipped_files} skipped, {new_blocks} new blocks, {dedup_blocks} dedup blocks", log=True)[1]
        log_msg = log_msg.format(file_count=file_count, skipped_files=skipped_files, new_blocks=new_blocks, dedup_blocks=dedup_blocks)
        log_lines.append(log_msg)
        log_msg = _("Data: {total_mb} MiB total → {stored_mb} MiB stored ({saved_pct}% saved)", log=True)[1]
        log_msg = log_msg.format(total_mb=f"{total_mb:.2f}",
                         stored_mb=f"{stored_mb:.2f}",
                         saved_pct=f"{saved_pct:.2f}")
        log_lines.append(log_msg)
        log_msg = _("Duration: {duration}", log=True)[1]
        log_msg = log_msg.format(duration=duration)
        log_lines.append(log_msg)

        self._close_prev_index()
        self.server.finalize_snapshot(snap_name,
                                      total_bytes=total_bytes,
                                      stored_bytes=stored_bytes)
        log_msg = _("Snapshot: {snap_name}", log=True)[1]
        log_msg = log_msg.format(snap_name=self.server.snap_dir(snap_name))

        for line in log_lines:
            self.logger.info(line)

        result = {'snap_name':snap_name, 'log':log_lines}
        return result

    def restore(self, snap_name: str, dest: str,
                filter_path: Optional[str] = None,
                dry_run: bool = False) -> None:
        """Restore a snapshot (or a single file/dir) to dest.

        Refuses to run with the wrong key for the repository, see
        verify_key().
        """
        self.server.lock_repo()
        try:
            # Say which key is wrong instead of failing somewhere in the
            # middle on a path we cannot decrypt.
            self.verify_key()
            self._restore_locked(snap_name, dest, filter_path, dry_run)
        finally:
            self.server.unlock_repo()

    def _restore_locked(self, snap_name, dest, filter_path, dry_run):
        if filter_path is not None:
            self.logger.info("Restoring '%s:%s' → %s", snap_name, filter_path, dest)
        else:
            self.logger.info("Restoring '%s' → %s", snap_name, dest)

        dest = os.path.abspath(dest)

        # Encrypt filter_path for server-side prefix matching
        enc_filter = self.encrypt_rel_path(filter_path) if filter_path else None

        # Use cursor-based iteration to avoid loading all entries into RAM.
        # Determine single-file restore from the first entry.
        self.server.open_entry_cursor(snap_name, enc_filter, full=True)
        first_batch = self.server.next_entries(2)
        if not first_batch:
            self.server.close_entry_cursor()
            self.logger.warning("No entries found")
            return
        single_file = (len(first_batch) == 1 and first_batch[0]["type"] != "dir")

        restored = []  # (dst_path, entry) for deferred metadata
        deferred_hardlinks = []  # (dst_entry, link_src, entry) created after all files

        # Process the first batch, then continue reading
        pending = first_batch
        while pending:
            for entry in pending:
                # Decrypt rel_path from server
                entry["rel_path"] = self.decrypt_rel_path(entry["rel_path"])
                if entry.get("link_target"):
                    entry["link_target"] = self.decrypt_rel_path(entry["link_target"])
                if entry.get("symlink_target"):
                    entry["symlink_target"] = self.decrypt_symlink_target(entry["symlink_target"])
                # Compute display-relative paths after decryption
                if filter_path is not None:
                    entry["rel_path"] = os.path.relpath(entry["rel_path"], filter_path) if entry["rel_path"] != filter_path else "."
                    if entry.get("link_target"):
                        entry["link_target"] = os.path.relpath(entry["link_target"], filter_path)

                if single_file:
                    dst_entry = dest
                else:
                    rel = entry["rel_path"]
                    dst_entry = os.path.join(dest, rel) if rel != "." else dest

                entry_type = entry["type"]

                if dry_run:
                    rel = entry["rel_path"]
                    msg = "{entry_type}\t{rel}"
                    msg = msg.format(entry_type=entry_type, rel=rel)
                    print(msg)
                    continue

                try:
                    if entry_type == "dir":
                        os.makedirs(dst_entry, exist_ok=True)

                    elif entry_type == "symlink":
                        os.makedirs(os.path.dirname(dst_entry), exist_ok=True)
                        if os.path.lexists(dst_entry):
                            os.unlink(dst_entry)
                        os.symlink(entry["symlink_target"], dst_entry)

                    elif entry_type == "hardlink":
                        link_target = entry["link_target"]
                        link_src = os.path.join(dest, link_target)
                        deferred_hardlinks.append((dst_entry, link_src, entry))
                        continue

                    elif entry_type in ("blockdev", "chardev"):
                        os.makedirs(os.path.dirname(dst_entry), exist_ok=True)
                        if os.path.lexists(dst_entry):
                            os.unlink(dst_entry)
                        dev = os.makedev(entry["devmajor"], entry["devminor"])
                        dev_mode = stat.S_IFBLK if entry_type == "blockdev" else stat.S_IFCHR
                        os.mknod(dst_entry, dev_mode | stat.S_IMODE(entry["mode"]), dev)

                    elif entry_type == "fifo":
                        os.makedirs(os.path.dirname(dst_entry), exist_ok=True)
                        if os.path.lexists(dst_entry):
                            os.unlink(dst_entry)
                        os.mkfifo(dst_entry, stat.S_IMODE(entry["mode"]))

                    elif entry_type == "socket":
                        os.makedirs(os.path.dirname(dst_entry), exist_ok=True)
                        if os.path.lexists(dst_entry):
                            os.unlink(dst_entry)
                        os.mknod(dst_entry, stat.S_IFSOCK | stat.S_IMODE(entry["mode"]))

                    elif entry_type == "file":
                        os.makedirs(os.path.dirname(dst_entry), exist_ok=True)
                        msg = "Restoring file: {file}"
                        msg = msg.format(file=dst_entry)
                        self.logger.info(msg)
                        with open(dst_entry, "wb") as fh:
                            for h in entry["chunk_hashes"]:
                                encrypted_blob = self.server.retrieve_block(h)
                                fh.write(self.decrypt_block(encrypted_blob))

                except (PermissionError, OSError) as exc:
                    self.logger.warning("Skipping %s: %s", dst_entry, exc)
                    continue

                restored.append((dst_entry, entry))

            pending = self.server.next_entries(10000)

        self.server.close_entry_cursor()

        # Create hardlinks now that all target files exist
        for dst_entry, link_src, entry in deferred_hardlinks:
            try:
                os.makedirs(os.path.dirname(dst_entry), exist_ok=True)
                if os.path.lexists(dst_entry):
                    os.unlink(dst_entry)
                os.link(link_src, dst_entry)
            except (PermissionError, OSError) as exc:
                self.logger.warning("Skipping %s: %s", dst_entry, exc)
                continue
            restored.append((dst_entry, entry))

        # Restore metadata (deepest first)
        for dst_path, entry in sorted(restored, key=lambda e: e[0], reverse=True):
            if not os.path.lexists(dst_path):
                continue
            is_link = (entry["type"] == "symlink")
            try:
                os.lchown(dst_path, entry["uid"], entry["gid"])
            except (PermissionError, OSError) as exc:
                self.logger.debug("lchown %s: %s", dst_path, exc)
            is_dir = (entry["type"] == "dir")
            if not is_link:
                # Same as in set_entry_metadata(): clear first, then set what
                # this entry has. The destination may exist already, and what
                # we create inherits an ACL from a default ACL above it.
                _remove_acl(dst_path)
                if is_dir:
                    _remove_acl(dst_path, default=True)
                try:
                    os.chmod(dst_path, stat.S_IMODE(entry["mode"]))
                except (PermissionError, OSError) as exc:
                    self.logger.debug("chmod %s: %s", dst_path, exc)
                if entry.get("acl"):
                    _set_acl_text(dst_path, entry["acl"])
                if entry.get("default_acl") and is_dir:
                    _set_default_acl_text(dst_path, entry["default_acl"])
            # After the chown above: that drops security.capability. Symlinks
            # get their attributes too, setxattr() does not follow the link.
            if entry.get("xattrs"):
                _set_xattrs(dst_path, entry["xattrs"])
            try:
                os.utime(dst_path, (entry["atime"], entry["mtime"]), follow_symlinks=False)
            except (OSError, AttributeError):
                pass

        self.logger.info("Restore complete: %s", dest)

    def print_contents(self, snap_name: str,
                       filter_path: Optional[str] = None,
                       full_path: bool = False,
                       recursive: bool = False) -> None:
        """Print snapshot contents chunk-wise (no RAM accumulation)."""
        enc_filter = self.encrypt_rel_path(filter_path) if filter_path else None
        self.server.open_entry_cursor(snap_name, enc_filter)
        try:
            found = False
            while True:
                batch = self.server.next_entries(10000)
                if not batch:
                    break
                # Decrypt rel_paths and compute display-relative paths
                filtered_batch = []
                for entry in batch:
                    entry["rel_path"] = self.decrypt_rel_path(entry["rel_path"])
                    if filter_path is not None:
                        rel = os.path.relpath(entry["rel_path"], filter_path) if entry["rel_path"] != filter_path else "."
                        # Without --recursive, skip entries deeper than direct children
                        if not recursive and rel != "." and "/" in rel:
                            continue
                        if not full_path:
                            entry["rel_path"] = rel
                    elif not recursive and entry["rel_path"] != "." and "/" in entry["rel_path"]:
                        continue
                    if entry.get("link_target"):
                        entry["link_target"] = self.decrypt_rel_path(entry["link_target"])
                    if entry.get("symlink_target"):
                        entry["symlink_target"] = self.decrypt_symlink_target(entry["symlink_target"])
                    filtered_batch.append(entry)
                if filtered_batch:
                    found = True
                    for line in self.format_contents(filtered_batch):
                        print(line)
            if not found:
                print("No entries found.")
        finally:
            self.server.close_entry_cursor()

    @staticmethod
    def format_contents(entries: list) -> list:
        """Format a list of snapshot entries into human-readable strings.

        Output resembles ls -l: type+perms owner:group size mtime path
        """
        _type_char = {
            "file": "-", "dir": "d", "symlink": "l", "hardlink": "h",
            "blockdev": "b", "chardev": "c", "fifo": "p", "socket": "s",
        }
        def _mode_str(mode_int):
            """Convert mode bits to rwxrwxrwx string."""
            m = stat.S_IMODE(mode_int)
            parts = []
            for shift in (6, 3, 0):
                parts.append("r" if m & (4 << shift) else "-")
                parts.append("w" if m & (2 << shift) else "-")
                parts.append("x" if m & (1 << shift) else "-")
            s = list("".join(parts))
            if m & stat.S_ISUID:
                s[2] = "s" if s[2] == "x" else "S"
            if m & stat.S_ISGID:
                s[5] = "s" if s[5] == "x" else "S"
            if m & stat.S_ISVTX:
                s[8] = "t" if s[8] == "x" else "T"
            return "".join(s)

        lines = []
        for e in entries:
            tc = _type_char.get(e["type"], "?")
            perms = _mode_str(e.get("mode", 0))
            size = e.get("size", 0)
            mtime = e.get("mtime", 0)
            mtime_str = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M") if mtime else "                "
            rel = e["rel_path"]
            suffix = ""
            if e["type"] == "symlink":
                suffix = f" -> {e.get('symlink_target', '')}"
            elif e["type"] == "hardlink":
                suffix = f" => {e.get('link_target', '')}"
            lines.append(
                f"{tc}{perms} {e.get('uid', 0):>5}:{e.get('gid', 0):<5} {size:>10} {mtime_str}  {rel}{suffix}"
            )
        return lines


# ---------------------------------------------------------------------------
# Verify (uses both server and client)
# ---------------------------------------------------------------------------

def cmd_verify(server: BackupServer, client: BackupClient, snap_name: str) -> bool:
    server.lock_repo()
    server.load_pack_index()
    try:
        return _cmd_verify_locked(server, client, snap_name)
    finally:
        server.unlock_repo()


def _cmd_verify_locked(server: BackupServer, client: BackupClient, snap_name: str) -> bool:
    snap_id = server._resolve_snap_id(snap_name)
    if snap_id == 0:
        raise FileNotFoundError(f"Snapshot not found: {snap_name}")

    errors = 0
    checked = 0

    for rel_path, val in server._iter_snap_index(snap_name):
        parsed = server._parse_index_entry(val)
        if parsed is None or parsed["type"] != "file":
            continue

        if server.mode == "pack":
            # Pack mode: chunk_hashes are in the index
            chunk_hashes = parsed.get("chunk_hashes", [])
        else:
            tree_path = server._tree_entry_path(rel_path, snap_name)
            try:
                lines = server._read_gz(tree_path).strip().split("\n")
                chunk_hashes = [h for h in lines[2:] if h] if len(lines) > 2 else []
            except OSError:
                logger.error("Missing tree entry for %s", rel_path)
                errors += 1
                continue

        for h in chunk_hashes:
            if not h:
                continue
            checked += 1

            # Check block exists
            if not server.block_exists(h):
                logger.error("Missing block %s  (%s)", h[:16], rel_path)
                errors += 1
                continue

            # Decrypt and verify hash
            try:
                encrypted_blob = server.retrieve_block(h)
                data = client.decrypt_block(encrypted_blob)
            except Exception as exc:
                logger.error("Decrypt error %s  (%s): %s", h[:16], rel_path, exc)
                errors += 1
                continue

            if client.hash_block(data) != h:
                logger.error("Hash mismatch %s  (%s)", h[:16], rel_path)
                errors += 1

    if errors == 0:
        print(f"OK  {snap_name}: {checked} blocks verified")
        return True
    print(f"FAILED  {snap_name}: {errors}/{checked} blocks with errors")
    return False
