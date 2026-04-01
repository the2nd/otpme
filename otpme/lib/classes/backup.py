# -*- coding: utf-8 -*-
# NOTE: This module was written by claude code!
import os
import stat
import gzip
import zlib
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



def _entry_ctime(val):
    """Extract ctime from a binary snap-index entry without full parse."""
    return struct.unpack_from('>d', val, _SNAP_CTIME_OFFSET)[0]


def _entry_chunk_hashes(val):
    """Extract chunk hashes from a binary snap-index entry without full parse."""
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
except:
    pass

from otpme.lib import config

from otpme.lib.exceptions import *

"""
OTPMe Backup - Deduplicated, encrypted backup with filesystem-native metadata.

Architecture
============

  BackupClient (crypto + file I/O)     BackupServer (storage only)
  ──────────────────────────────────    ──────────────────────────────
   Filesystem read                       get_salt() → bytes
   Metadata collection                   block_exists(hash) → bool
   SHA-256 hashing                       store_block(hash, blob)
   zlib compression                      retrieve_block(hash) → blob
   AES-GCM encryption                   create_snapshot(name)
   ───── sends encrypted blob ────→      write_entry(name, path, meta)
   ←──── receives encrypted blob ──
   AES-GCM decryption                   iter_entries(name) → entry...
   zlib decompression                    list_snapshots() → [...]
   File writing + metadata restore       delete_snapshot(name)
                                         gc_orphaned_blocks()

  The server never sees plaintext.  The client knows nothing about storage layout.

Storage layout
==============

  backup_dir/
  ├── key.salt                   # PBKDF2 salt (600 000 iterations → AES-256 key)
  ├── packs/                     # Pack-based encrypted block store
  │   ├── XX/                   #   first 2 hex chars of 6-digit pack ID
  │   │   └── pack-XXXXXX.dat  #   concatenated entries: 64B hash + 4B len + blob
  │   └── pack_index.db         #   SQLite pack index: hash → (pack_id, offset, length)
  ├── tree/                      # Shared directory tree with all backup entries
  │   ├── etc/                  #   mirrors the original directory structure
  │   │   └── cfg-<snap>        #   files get "-<snap_name>" suffix
  │   └── home/
  │       └── user/
  │           └── doc-<snap>
  └── snapshots/
      └── <name>/
          ├── meta/              # Only for directories: sha256(rel_path) named files
          │   └── <hash_b>       # standalone file for dirs (metadata carrier)
          ├── entry_ids.gz        # Compressed entry_id list (per snapshot)
          └── snap_index.db       # SQLite: entries table + key index

  For directories, meta/ files carry filesystem metadata (permissions, ACLs,
  ownership, timestamps) as actual file attributes.  For non-directory entries,
  metadata is stored directly on the tree/ file — no meta/ entry exists.

File content format (meta/ and tree/ entries)
=============================================

  <rel_path>                      ← line 0: original relative path
  <size> <mtime>                  ← line 1 (regular files): decimal size + mtime
  <sha256_chunk_hash_1>           ← lines 2+: one hash per line, in order
  <sha256_chunk_hash_2>
  ...

  Special entry types use a type marker on line 1:
  DIR, SYMLINK, HARDLINK, BLOCKDEV, CHARDEV, FIFO, SOCKET

Snapshot deletion & garbage collection
======================================

  1. Read index — for non-dir entries, delete tree/ file (via suffix)
  2. Remove snapshots/<name>/ directory
  3. Clean up empty tree/ directories (bottom-up)
  4. Scan all remaining snapshot chunks files to collect live hashes
  5. Remove dead hashes from pack index; delete fully empty pack files
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


def _derive_path_key(key: bytes) -> bytes:
    """Derive a 64-byte AES-SIV key from the 32-byte main key."""
    # Two HMAC rounds to get 64 bytes (2×32)
    k1 = _hmac.new(key, _PATH_KEY_LABEL + b'\x01', 'sha256').digest()
    k2 = _hmac.new(key, _PATH_KEY_LABEL + b'\x02', 'sha256').digest()
    return k1 + k2


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
    """Manages the backup storage: objects/, snapshots/, salt.

    The server never sees plaintext data.  It stores and retrieves
    pre-encrypted blobs identified by their plaintext SHA-256 hash.
    """

    def __init__(self, backup_dir: str):
        self.root          = Path(backup_dir)
        self.packs_dir     = self.root / "packs"
        self.tree_dir      = self.root / "tree"
        self.snapshots_dir = self.root / "snapshots"
        self.salt_file     = self.root / "key.salt"
        self.mode_file     = self.root / "mode"
        self.mode          = None  # loaded by _load_mode()
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
        self._snap_id_cache     = {}    # snap_name -> snap_id
        self._snap_entry_id_cache = {}  # snap_name -> set of entry_ids
        self._active_snap_id    = None  # snap_id of current write session
        self._active_entry_ids  = None  # set of entry_ids being written
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
        except (OSError, IOError):
            fd.close()
            raise RuntimeError("Backup repository is locked by another process.")
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

    def _snap_entry_ids(self, snap_name: str) -> set:
        """Return cached set of entry_ids for a snapshot."""
        if snap_name in self._snap_entry_id_cache:
            return self._snap_entry_id_cache[snap_name]
        ids = self._read_snap_entry_ids(snap_name)
        self._snap_entry_id_cache[snap_name] = ids
        return ids

    def _snap_index_get(self, snap_name: str, rel_path: str) -> bytes:
        """Look up a single entry from snap-index SQLite. Returns entry_data or None."""
        entry_ids = self._snap_entry_ids(snap_name)
        if not entry_ids:
            return None
        db = self._snap_db
        if db is None:
            db_path = self._snap_index_db_path()
            if not os.path.exists(db_path):
                return None
            db = sqlite3.connect(db_path)
            try:
                for row in db.execute(
                        "SELECT entry_id, value FROM entries WHERE key=? ORDER BY entry_id DESC",
                        (rel_path,)):
                    if row[0] in entry_ids:
                        return row[1]
                return None
            finally:
                db.close()
        for row in db.execute(
                "SELECT entry_id, value FROM entries WHERE key=? ORDER BY entry_id DESC",
                (rel_path,)):
            if row[0] in entry_ids:
                return row[1]
        return None

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

    def store_block(self, h: str, blob: bytes) -> None:
        """Append a pre-encrypted blob to the active pack file."""
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

    @staticmethod
    def _path_hash(rel_path: str) -> str:
        """Return SHA-256 hex digest of a relative path (used for meta/ filenames)."""
        return hashlib.sha256(rel_path.encode("utf-8")).hexdigest()

    def _gen_hash_name(self, name: str, snap_name: str) -> str:
        short = hashlib.sha1(name.encode("utf-8")).hexdigest()[:16]
        tree_name = f"{short}-{snap_name}.longname"
        return tree_name

    def _tree_entry_path(self, rel_path: str, snap_name: str) -> str:
        """Return the full path for a non-directory entry in tree/."""
        dirname = os.path.dirname(rel_path)
        basename = os.path.basename(rel_path)
        tree_name = f"{basename}-{snap_name}"
        if len(tree_name.encode("utf-8")) > 255:
            tree_name = self._gen_hash_name(basename, snap_name)
        if dirname:
            return os.path.join(str(self.tree_dir), dirname, tree_name)
        return os.path.join(str(self.tree_dir), tree_name)

    def _meta_entry_path(self, snap_name: str, rel_path: str) -> str:
        """Return bucketed path for a meta/ entry: meta/XX/<hash>."""
        path_hash = self._path_hash(rel_path)
        meta_dir = str(self.snap_meta_dir(snap_name))
        return os.path.join(meta_dir, path_hash[:2], path_hash)

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

    def _snap_entry_ids_path(self, snap_name: str) -> Path:
        """Return path to the entry_ids.gz file for a snapshot."""
        return self.snap_dir(snap_name) / "entry_ids.gz"

    def _write_snap_entry_ids(self, snap_name: str, entry_ids) -> None:
        """Write entry_ids set/list to a compressed file."""
        sorted_ids = sorted(entry_ids)
        raw = struct.pack(f'>{len(sorted_ids)}Q', *sorted_ids)
        path = self._snap_entry_ids_path(snap_name)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(str(path), 'wb') as f:
            f.write(zlib.compress(raw))

    def _read_snap_entry_ids(self, snap_name: str) -> set:
        """Read entry_ids from compressed file. Returns empty set if missing."""
        path = self._snap_entry_ids_path(snap_name)
        if not path.exists():
            return set()
        raw = zlib.decompress(path.read_bytes())
        count = len(raw) // 8
        return set(struct.unpack(f'>{count}Q', raw))

    # -- snapshot management --

    def snap_meta_dir(self, name: str) -> Path:
        return self.snapshots_dir / name / "meta"


    def snap_dir(self, name: str) -> Path:
        return self.snapshots_dir / name

    def _snap_index_db_path(self) -> str:
        """Return path for the shared snap-index SQLite database."""
        return str(self.root / "snap_index.db")

    def snap_chunks_path(self, name: str) -> Path:
        """Return path to the snapshot chunks file."""
        return self.snap_dir(name) / "chunks"

    def _open_snap_db(self, readonly: bool = False) -> sqlite3.Connection:
        """Open the shared snap-index SQLite database."""
        if self._snap_db is not None:
            return self._snap_db
        db_path = self._snap_index_db_path()
        if readonly and not os.path.exists(db_path):
            return None
        uri = f"file:{db_path}?mode=ro" if readonly else db_path
        if readonly:
            db = sqlite3.connect(uri, uri=True)
        else:
            db = sqlite3.connect(db_path)
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=NORMAL")
        db.execute("PRAGMA cache_size=-65536")  # 64 MiB cache
        if not readonly:
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

        self._snap_db = db
        return db

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
            db_path = self._snap_index_db_path()
            if not os.path.exists(db_path):
                return 0
            db = sqlite3.connect(db_path)
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
        self._active_entry_ids = set()
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
        # Write entry_ids to compressed file
        if self._active_entry_ids is not None and self._active_snap_name:
            self._write_snap_entry_ids(self._active_snap_name, self._active_entry_ids)
            self._active_entry_ids = None
            self._active_snap_name = None
        if self._snap_db is not None:
            self._snap_db.commit()
            self._snap_db.close()
            self._snap_db = None
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
        self._active_entry_ids.add(entry_id)
        # Stream chunk hashes to chunks file
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
            from_ids = self._snap_entry_ids(from_snap)
            if from_ids:
                for row in self._snap_db.execute(
                        "SELECT entry_id FROM entries WHERE key=? ORDER BY entry_id DESC",
                        (rel_path,)):
                    if row[0] in from_ids:
                        entry_id = row[0]
                        break
        if entry_id is None:
            row = self._snap_db.execute(
                "SELECT entry_id FROM entries WHERE key=? ORDER BY entry_id DESC LIMIT 1",
                (rel_path,)).fetchone()
            if row is None:
                return
            entry_id = row[0]
        self._active_entry_ids.add(entry_id)
        # Stream chunk hashes to chunks file
        if self._chunks_gz is not None:
            val = self._snap_db.execute(
                "SELECT value FROM entries WHERE entry_id=?",
                (entry_id,)).fetchone()[0]
            for h in _entry_chunk_hashes(val):
                self._chunks_gz.write(h + '\n')

    def _iter_snap_index(self, snap_name: str):
        """Yield (rel_path, entry_data_bytes) tuples for a snapshot from SQLite."""
        entry_ids = self._snap_entry_ids(snap_name)
        if not entry_ids:
            return
        db_path = self._snap_index_db_path()
        if not os.path.exists(db_path):
            return
        db = sqlite3.connect(db_path)
        try:
            # Batch-fetch entries by entry_id, sort by key
            results = []
            id_list = sorted(entry_ids)
            for i in range(0, len(id_list), 500):
                batch = id_list[i:i+500]
                ph = ",".join("?" * len(batch))
                for eid, key, val in db.execute(
                        f"SELECT entry_id, key, value FROM entries "
                        f"WHERE entry_id IN ({ph})", batch):
                    results.append((key, val))
            results.sort(key=lambda x: x[0])
            for key, val in results:
                yield key, val
        finally:
            db.close()


    def read_chunks_file(self, snap_name: str) -> set:
        """Read the chunks file and return a set of chunk hashes."""
        return set(self.iter_chunks_file(snap_name))

    def iter_chunks_file(self, snap_name: str):
        """Yield chunk hashes from the chunks file one at a time (streaming)."""
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

        Format: 43-byte header + 2-byte extra_len + extra + 2-byte acl_len + acl
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
        return header + struct.pack('>H', len(extra)) + extra + struct.pack('>H', len(acl)) + acl

    @staticmethod
    def _parse_index_entry(val: bytes) -> Optional[dict]:
        """Parse a binary snap-index value into a dict.

        Returns dict with type, mode, uid, gid, size, ctime, mtime, atime,
        and optionally symlink_target, link_target, devmajor, devminor, chunk_hashes, acl.
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

    def get_snap_entry_ids(self, snap_name: str) -> bytes:
        """Return the compressed entry_ids blob for a snapshot, or b'' if missing."""
        path = self._snap_entry_ids_path(snap_name)
        if path.exists():
            return path.read_bytes()
        return b''

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
        """Create meta/ directory and index file for a new snapshot."""
        self.file_count = 0
        self.inode_count = 0
        self.ref_count = 0
        self.start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if self.mode != "pack":
            self.snap_meta_dir(name).mkdir(parents=True, exist_ok=True)
        else:
            self.snap_dir(name).mkdir(parents=True, exist_ok=True)
        # Open snap-index session for this snapshot
        self._open_snap_session(name)

    def set_running(self, name: str) -> None:
        """Write a pidfile to mark the snapshot as currently running."""
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

        For directories: creates the dir in tree/ and a metadata file in meta/.
        For all other types: creates a file in tree/<dir>/<name>-<snap>.

        File content format:
            Line 1: relative path
            Line 2+: type-specific data

        Only creates the filesystem object — does NOT apply metadata.
        Call set_entry_metadata() after write_entry().  For directories,
        defer the call until all files are written (deepest-first) so
        that tree/ directory mtimes are not clobbered.
        """
        entry_type = meta["type"]

        if self.mode != "pack":
            if entry_type == "dir":
                tree_dir_path = os.path.join(str(self.tree_dir), rel_path) if rel_path != "." else str(self.tree_dir)
                os.makedirs(tree_dir_path, exist_ok=True)
                meta_path = self._meta_entry_path(snap_name, rel_path)
                os.makedirs(os.path.dirname(meta_path), exist_ok=True)
                self._write_gz(meta_path, f"{rel_path}\nDIR\n")
                self.inode_count += 1

            elif entry_type == "symlink":
                tree_path = self._tree_entry_path(rel_path, snap_name)
                os.makedirs(os.path.dirname(tree_path), exist_ok=True)
                self._write_gz(tree_path, f"{rel_path}\nSYMLINK\n{meta['symlink_target']}\n")
                self.file_count += 1
                self.inode_count += 1

            elif entry_type == "hardlink":
                tree_path = self._tree_entry_path(rel_path, snap_name)
                os.makedirs(os.path.dirname(tree_path), exist_ok=True)
                self._write_gz(tree_path, f"{rel_path}\nHARDLINK\n{meta['link_target']}\n")
                self.file_count += 1
                self.inode_count += 1

            elif entry_type in ("blockdev", "chardev"):
                tree_path = self._tree_entry_path(rel_path, snap_name)
                os.makedirs(os.path.dirname(tree_path), exist_ok=True)
                self._write_gz(tree_path, f"{rel_path}\n{entry_type.upper()}\n{meta['devmajor']} {meta['devminor']}\n")
                self.file_count += 1
                self.inode_count += 1

            elif entry_type in ("fifo", "socket"):
                tree_path = self._tree_entry_path(rel_path, snap_name)
                os.makedirs(os.path.dirname(tree_path), exist_ok=True)
                self._write_gz(tree_path, f"{rel_path}\n{entry_type.upper()}\n")
                self.file_count += 1
                self.inode_count += 1

            elif entry_type == "file":
                tree_path = self._tree_entry_path(rel_path, snap_name)
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

        For directories: applies to both the meta/ file and the tree/ dir.
        For non-dirs: applies directly to the tree/ file.

        meta dict keys:
            type:           "file" | "dir" | "symlink"
            mode:           int (file mode bits)
            uid, gid:       int
            atime, mtime:   float
            acl:            str or None
        """
        if self.mode == "pack":
            return
        if meta.get("type") == "dir":
            meta_path = self._meta_entry_path(snap_name, rel_path)
            tree_dir_path = os.path.join(str(self.tree_dir), rel_path) if rel_path != "." else str(self.tree_dir)
            targets = [meta_path, tree_dir_path]
        else:
            targets = [self._tree_entry_path(rel_path, snap_name)]

        for target in targets:
            try:
                os.chown(target, meta["uid"], meta["gid"])
            except (PermissionError, OSError) as exc:
                logger.debug("chown %s: %s", target, exc)

            try:
                os.chmod(target, stat.S_IMODE(meta["mode"]))
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
        if self.mode == "pack":
            return
        for rel_path, meta in sorted(dir_entries, key=lambda e: e[0], reverse=True):
            self.set_entry_metadata(snap_name, rel_path, meta)

    def get_entry_full(self, snap_name: str, rel_path: str) -> Optional[dict]:
        """Read all info for an entry in one shot (single lstat + open + ACL read).

        For non-dirs reads from tree/ file, for dirs from meta/ file.
        Returns dict with mode, uid, gid, mtime, acl, and for regular files
        also file_size, file_mtime, chunk_hashes.  Returns None if not found.
        """
        if self.mode == "pack":
            # Pack mode: O(1) index lookup
            parsed = self._snap_index_get_parsed(snap_name, rel_path)
            if parsed is None:
                return None
            result = {
                "mode": parsed["mode"],
                "uid": parsed["uid"],
                "gid": parsed["gid"],
                "mtime": parsed["mtime"],
                "acl": parsed.get("acl"),
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

        # Tree mode: read from tree/ and meta/ files
        tree_path = self._tree_entry_path(rel_path, snap_name)
        if os.path.lexists(tree_path):
            entry_path = tree_path
        else:
            # Fall back to meta/ (dirs, bucketed)
            entry_path = self._meta_entry_path(snap_name, rel_path)
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

        For directories: hardlinks meta/ file and ensures tree/ dir exists.
        For non-dirs: hardlinks tree/ file only (no meta/ entry).
        Returns True on success, False if source doesn't exist.

        index_val:  raw binary index value to copy into the new snapshot's index.
        meta:       dict to build index entry from (used when metadata changed).
        If neither is given, a minimal fallback entry is written.
        """
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
            # Ensure tree/ directory exists (shared across snapshots)
            tree_dir_path = os.path.join(str(self.tree_dir), rel_path) if rel_path != "." else str(self.tree_dir)
            os.makedirs(tree_dir_path, exist_ok=True)
            # Hardlink meta/ entry (dirs, bucketed)
            src_meta = self._meta_entry_path(from_snap, rel_path)
            dst_meta = self._meta_entry_path(to_snap, rel_path)
            if not os.path.lexists(src_meta):
                return False
            os.makedirs(os.path.dirname(dst_meta), exist_ok=True)
            os.link(src_meta, dst_meta)
        else:
            # Hardlink tree/ entry: old snap → new snap
            src_tree = self._tree_entry_path(rel_path, from_snap)
            dst_tree = self._tree_entry_path(rel_path, to_snap)
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
        - For tree mode: also hardlinks tree/meta filesystem entries

        Returns the number of successfully linked entries.
        """
        linked = 0

        if self.mode == "pack":
            for rel_path, is_dir in entries:
                self.file_count += 1
                self._snap_index_link(to_snap, rel_path, from_snap=from_snap)
                linked += 1
        else:
            for rel_path, is_dir in entries:
                if is_dir:
                    tree_dir_path = os.path.join(str(self.tree_dir), rel_path) if rel_path != "." else str(self.tree_dir)
                    os.makedirs(tree_dir_path, exist_ok=True)
                    src_meta = self._meta_entry_path(from_snap, rel_path)
                    dst_meta = self._meta_entry_path(to_snap, rel_path)
                    if not os.path.lexists(src_meta):
                        continue
                    os.makedirs(os.path.dirname(dst_meta), exist_ok=True)
                    os.link(src_meta, dst_meta)
                else:
                    src_tree = self._tree_entry_path(rel_path, from_snap)
                    dst_tree = self._tree_entry_path(rel_path, to_snap)
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
            if self.get_mode() == "pack":
                entry["atime"] = parsed.get("atime", 0.0)
                entry["acl"] = parsed.get("acl")
                if parsed["type"] == "file":
                    entry["chunk_hashes"] = parsed.get("chunk_hashes", [])
                else:
                    entry["chunk_hashes"] = []
            else:
                if parsed["type"] == "dir":
                    entry_path = self._meta_entry_path(snap_name, rel_path)
                else:
                    entry_path = self._tree_entry_path(rel_path, snap_name)
                st = os.lstat(entry_path)
                entry["atime"] = st.st_atime
                entry["acl"] = _get_acl_text(entry_path)
                if parsed["type"] == "file":
                    lines = self._read_gz(entry_path).strip().split("\n")
                    entry["chunk_hashes"] = [h for h in lines[2:] if h] if len(lines) > 2 else []
                else:
                    entry["chunk_hashes"] = []

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

        # Open DB first so _resolve_snap_id can use it (also runs migration)
        db = self._open_snap_db()
        if db is None:
            raise FileNotFoundError(f"Snapshot not found: {snap_name}")

        snap_id = self._resolve_snap_id(snap_name)
        if snap_id == 0:
            raise FileNotFoundError(f"Snapshot not found: {snap_name}")

        # Load entry_ids set for this snapshot
        entry_ids = self._snap_entry_ids(snap_name)

        if filter_path is not None:
            # Get candidate entries by key range, filter by snapshot membership
            candidates = db.execute(
                "SELECT entry_id, key, value FROM entries "
                "WHERE key=? OR (key>? AND key<?) ORDER BY key",
                (filter_path, filter_path + "/", filter_path + "/\xff\xff\xff\xff")).fetchall()
            # Deduplicate by key: keep latest entry_id (highest) per key
            results = {}
            for eid, key, val in candidates:
                if eid in entry_ids:
                    if key not in results or eid > results[key][0]:
                        results[key] = (eid, val)
            sorted_results = [(k, v) for k, (_, v) in sorted(results.items())]
            self._entry_cursor_results = iter(sorted_results)
        else:
            # Full scan: batch-fetch entries by entry_id, sort by key
            results = []
            id_list = sorted(entry_ids)
            for i in range(0, len(id_list), 500):
                batch = id_list[i:i+500]
                ph = ",".join("?" * len(batch))
                for eid, key, val in db.execute(
                        f"SELECT entry_id, key, value FROM entries "
                        f"WHERE entry_id IN ({ph})", batch):
                    results.append((key, val))
            results.sort(key=lambda x: x[0])
            self._entry_cursor_results = iter(results)

        self._entry_cursor_cur = True  # flag: cursor is open
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
        if hasattr(self, '_entry_cursor_cur') and self._entry_cursor_cur is not None:
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

        # Remove snapshot directory (meta/ + complete + running + chunks)
        shutil.rmtree(snap_dir)

    def _remove_snap_from_index(self, snap_name: str) -> None:
        """Remove a snapshot from the snap-index."""
        # Collect all entry_ids still referenced by other snapshots
        live_ids = set()
        for snap in self.snapshots_dir.iterdir():
            if snap.name == snap_name:
                continue
            ids_path = snap / "entry_ids.gz"
            if ids_path.exists():
                live_ids.update(self._read_snap_entry_ids(snap.name))

        # Remove entry_ids file for this snapshot
        ids_path = self._snap_entry_ids_path(snap_name)
        deleted_ids = set()
        if ids_path.exists():
            deleted_ids = self._read_snap_entry_ids(snap_name)
            ids_path.unlink()

        # Remove orphaned entries (not referenced by any other snapshot)
        orphan_ids = deleted_ids - live_ids
        if orphan_ids:
            db_path = self._snap_index_db_path()
            if os.path.exists(db_path):
                db = sqlite3.connect(db_path)
                db.execute("PRAGMA journal_mode=WAL")
                db.execute("PRAGMA synchronous=NORMAL")
                try:
                    id_list = sorted(orphan_ids)
                    for i in range(0, len(id_list), 500):
                        batch = id_list[i:i+500]
                        ph = ",".join("?" * len(batch))
                        db.execute(f"DELETE FROM entries WHERE entry_id IN ({ph})", batch)
                    db.commit()
                finally:
                    db.close()

        # Remove snap metadata
        db_path = self._snap_index_db_path()
        if os.path.exists(db_path):
            db = sqlite3.connect(db_path)
            try:
                db.execute("DELETE FROM snap_meta WHERE snap_name=?", (snap_name,))
                db.commit()
            finally:
                db.close()

        self._snap_id_cache.pop(snap_name, None)
        self._snap_entry_id_cache.pop(snap_name, None)

    def delete_snapshot(self, snap_name: str) -> int:
        """Delete a snapshot and run GC.  Returns number of orphaned blocks removed."""
        self.lock_repo()
        self.load_pack_index()
        try:
            return self._delete_snapshot_locked(snap_name)
        finally:
            self.unlock_repo()

    def _build_live_bloom(self, exclude_set: set = None):
        """Build a Bloom filter containing all chunk hashes from live snapshots.

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
                else:
                    to_delete.append(name)
                deleted.append(name)

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
        # Collect all live entry_ids from all snapshot gz files
        live_ids = set()
        if self.snapshots_dir.exists():
            for snap in self.snapshots_dir.iterdir():
                ids_path = snap / "entry_ids.gz"
                if ids_path.exists():
                    live_ids.update(self._read_snap_entry_ids(snap.name))
        # Remove entries not in any snapshot
        db = sqlite3.connect(db_path)
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=NORMAL")
        try:
            total = db.execute("SELECT COUNT(*) FROM entries").fetchone()[0]
            orphans = 0
            # Batch-check entries against live set
            for entry_id, in db.execute("SELECT entry_id FROM entries"):
                if entry_id not in live_ids:
                    db.execute("DELETE FROM entries WHERE entry_id=?", (entry_id,))
                    orphans += 1
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
# BackupClient — crypto + file I/O, no storage knowledge
# ---------------------------------------------------------------------------

class BackupClient:
    """Handles encryption/decryption and filesystem operations.

    The client never touches the storage layout directly.  All storage
    operations go through the server interface.
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
        else:
            self._siv = None

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

    @staticmethod
    def hash_block(plaintext: bytes) -> str:
        """Return the SHA-256 hex digest of a plaintext block."""
        return hashlib.sha256(plaintext).hexdigest()

    def encrypt_block(self, plaintext: bytes) -> bytes:
        """Compress (if enabled) and encrypt a plaintext block.  Returns flag+ciphertext."""
        if self.compress:
            compressed = zlib.compress(plaintext, COMPRESS_LEVEL)
            if len(compressed) < len(plaintext):
                return FLAG_ZLIB + encrypt_block(self.key, compressed)
        return FLAG_RAW + encrypt_block(self.key, plaintext)

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
        self._prev_entry_ids = None
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
            logger.info("Snap index cache is current, skipping download")
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
            logger.info("Snap index downloaded (%d bytes, %d compressed)",
                        total, transferred)
        self._prev_db = sqlite3.connect(cached_db)
        self._prev_snap = prev_snap
        # Download entry_ids for prev_snap
        entry_ids_blob = self.server.get_snap_entry_ids(prev_snap)
        if entry_ids_blob:
            cached_ids = os.path.join(cache_dir, "entry_ids.gz")
            with open(cached_ids, 'wb') as f:
                f.write(entry_ids_blob)
            raw = zlib.decompress(entry_ids_blob)
            count = len(raw) // 8
            self._prev_entry_ids = set(struct.unpack(f'>{count}Q', raw))

    def _prev_index_get(self, rel_path: str) -> bytes:
        """Look up a path in the previous snapshot's index. Returns entry_data or None."""
        if self._prev_snap is None:
            return None
        if isinstance(self.server, BackupServer):
            # Local: direct lookup via server's snap-index
            return self.server._snap_index_get(self._prev_snap, rel_path)
        # Remote: lookup in local cached copy
        if self._prev_db is None:
            return None
        if self._prev_entry_ids is None:
            return None
        for row in self._prev_db.execute(
                "SELECT entry_id, value FROM entries WHERE key=? ORDER BY entry_id DESC",
                (rel_path,)):
            if row[0] in self._prev_entry_ids:
                return row[1]
        return None

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
        self._prev_entry_ids = None
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
        """
        source = os.path.realpath(source)
        if not os.path.isdir(source):
            raise ValueError(f"Not a directory: {source}")

        snap_name = name or datetime.now().strftime("%Y-%m-%dT%H-%M-%S")

        if not dry_run:
            self.server.lock_repo()
        try:
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

        # Two passes:
        #   create entries via server + store blocks, apply metadata inline

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
            logger.info("Dry run: %s", source)
        else:
            logger.info("Backing up %s → '%s'", source, snap_name)

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
                logger.debug("Skipping special file %s", fpath)
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

            try:
                if entry_type == "dir":
                    meta = {
                        "type": "dir",
                        "mode": mode,
                        "uid": st.st_uid, "gid": st.st_gid,
                        "atime": st.st_atime, "mtime": st.st_mtime,
                        "acl": _get_acl_text(fpath),
                        "ctime": st.st_ctime,
                    }
                    # Reuse previous snapshot's meta/ entry if unchanged
                    linked = False
                    if prev_snap:
                        prev = self.server.get_entry_full(prev_snap, enc_rel)
                        cur_acl = meta["acl"]
                        if (prev
                                and prev["uid"] == st.st_uid
                                and prev["gid"] == st.st_gid
                                and stat.S_IMODE(prev["mode"]) == stat.S_IMODE(mode)
                                and prev.get("mtime") == st.st_mtime
                                and prev["acl"] == cur_acl):
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
                                    "size": st.st_size,
                                    "chunk_hashes": chunk_hashes,
                                }
                                self.server.write_entry(snap_name, enc_rel, meta)
                                if repo_mode != "pack":
                                    self.server.set_entry_metadata(snap_name, enc_rel, meta)
                            skipped_files += 1
                            skipped = True

                    if not skipped:
                        logger.info("Processing file: %s", fpath)
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
                                logger.warning("File changed during backup: %s", fpath)
                        except OSError:
                            logger.warning("File vanished during backup: %s", fpath)

                        meta = {
                            "type": "file",
                            "mode": mode,
                            "uid": st.st_uid, "gid": st.st_gid,
                            "atime": st.st_atime, "mtime": st.st_mtime,
                            "ctime": st.st_ctime,
                            "acl": _get_acl_text(fpath),
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
                        "symlink_target": os.readlink(fpath),
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
                logger.warning("Skipping %s: %s", fpath, exc)

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
            logger.info("Processing changed directories: %d", len(dir_entries))
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

        logger.info("Done: %d files, %d skipped, %d new blocks, %d dedup blocks", file_count, skipped_files, new_blocks, dedup_blocks)
        logger.info("Data: %.1f MiB total → %.1f MiB stored (%.1f%% saved)", total_mb, stored_mb, saved_pct)
        logger.info("Duration: %s", duration)
        self._close_prev_index()
        self.server.finalize_snapshot(snap_name,
                                      total_bytes=total_bytes,
                                      stored_bytes=stored_bytes)
        logger.info("Snapshot: %s", self.server.snap_dir(snap_name))
        return snap_name

    def restore(self, snap_name: str, dest: str,
                filter_path: Optional[str] = None,
                dry_run: bool = False) -> None:
        """Restore a snapshot (or a single file/dir) to dest."""
        self.server.lock_repo()
        try:
            self._restore_locked(snap_name, dest, filter_path, dry_run)
        finally:
            self.server.unlock_repo()

    def _restore_locked(self, snap_name, dest, filter_path, dry_run):
        if filter_path is not None:
            logger.info("Restoring '%s:%s' → %s", snap_name, filter_path, dest)
        else:
            logger.info("Restoring '%s' → %s", snap_name, dest)

        dest = os.path.abspath(dest)

        # Encrypt filter_path for server-side prefix matching
        enc_filter = self.encrypt_rel_path(filter_path) if filter_path else None

        # Use cursor-based iteration to avoid loading all entries into RAM.
        # Determine single-file restore from the first entry.
        self.server.open_entry_cursor(snap_name, enc_filter, full=True)
        first_batch = self.server.next_entries(2)
        if not first_batch:
            self.server.close_entry_cursor()
            logger.warning("No entries found")
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
                        logger.info(msg)
                        with open(dst_entry, "wb") as fh:
                            for h in entry["chunk_hashes"]:
                                encrypted_blob = self.server.retrieve_block(h)
                                fh.write(self.decrypt_block(encrypted_blob))

                except (PermissionError, OSError) as exc:
                    logger.warning("Skipping %s: %s", dst_entry, exc)
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
                logger.warning("Skipping %s: %s", dst_entry, exc)
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
                logger.debug("lchown %s: %s", dst_path, exc)
            if not is_link:
                try:
                    os.chmod(dst_path, stat.S_IMODE(entry["mode"]))
                except (PermissionError, OSError) as exc:
                    logger.debug("chmod %s: %s", dst_path, exc)
                if entry.get("acl"):
                    _set_acl_text(dst_path, entry["acl"])
            try:
                os.utime(dst_path, (entry["atime"], entry["mtime"]), follow_symlinks=False)
            except (OSError, AttributeError):
                pass

        logger.info("Restore complete: %s", dest)

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

            if hashlib.sha256(data).hexdigest() != h:
                logger.error("Hash mismatch %s  (%s)", h[:16], rel_path)
                errors += 1

    if errors == 0:
        print(f"OK  {snap_name}: {checked} blocks verified")
        return True
    print(f"FAILED  {snap_name}: {errors}/{checked} blocks with errors")
    return False
