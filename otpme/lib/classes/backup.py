# -*- coding: utf-8 -*-
# NOTE: This module was written by claude code!
import os
import stat
import gzip
import zlib
import fcntl
import shutil
import struct
import fnmatch
import posix1e
import hashlib
from pathlib import Path
from typing import Optional
import time
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes as crypto_hashes

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
   AES-GCM decryption                   list_entries(name) → [entry...]
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
  │   └── index.gz              #   gzip master index: hash\\tpack_id\\toffset\\tlength
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
          └── index              # Tab-separated index of all entries (gzip-compressed)

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
  6. Flush updated index.gz atomically

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
        self._pack_index        = {}    # hash -> (pack_id, offset, length)
        self._pack_index_loaded = False
        self._active_pack_fd    = None
        self._active_pack_id    = None
        self._active_pack_size  = 0
        self._max_pack_size     = 512 * 1024 * 1024  # 512 MiB
        self._index_dirty       = False
        # Parsed snapshot index cache for pack mode (snap_name -> {rel_path -> parsed})
        self._snap_index_cache  = {}
        self._snap_index_cache_name = None

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
        self.load_pack_index()

    def unlock_repo(self) -> None:
        """Release the repository lock (reentrant)."""
        if self._lock_count > 1:
            self._lock_count -= 1
            return
        self._seal_active_pack()
        self._flush_pack_index()
        self._pack_index_loaded = False
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
            self.mode = "tree"

    def get_mode(self) -> str:
        """Return the repository mode ('tree' or 'pack')."""
        if self.mode is None:
            self._load_mode()
        return self.mode

    def _get_parsed_snap_index(self, snap_name: str) -> dict:
        """Return {rel_path: parsed_dict} for a snapshot, cached."""
        if self._snap_index_cache_name == snap_name:
            return self._snap_index_cache
        content = self._read_index_file(snap_name)
        result = {}
        if content:
            for line in content.strip().split("\n"):
                if not line:
                    continue
                parsed = self._parse_index_line(line)
                if parsed is None:
                    continue
                result[parsed["rel_path"]] = parsed
        self._snap_index_cache = result
        self._snap_index_cache_name = snap_name
        return result

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

    # -- pack index persistence --

    def load_pack_index(self) -> None:
        """Load packs/index.gz into self._pack_index."""
        if self._pack_index_loaded:
            return
        idx_path = self.packs_dir / "index.gz"
        self._pack_index = {}
        if idx_path.exists():
            raw = gzip.decompress(idx_path.read_bytes()).decode('utf-8')
            for line in raw.split('\n'):
                if not line:
                    continue
                parts = line.split('\t')
                if len(parts) != 4:
                    continue
                h, pack_id, offset, length = parts
                self._pack_index[h] = (int(pack_id), int(offset), int(length))
        self._pack_index_loaded = True
        self._index_dirty = False

    def _flush_pack_index(self) -> None:
        """Atomically write self._pack_index to packs/index.gz."""
        if not self._index_dirty:
            return
        self.packs_dir.mkdir(parents=True, exist_ok=True)
        lines = []
        for h, (pack_id, offset, length) in self._pack_index.items():
            lines.append(f"{h}\t{pack_id}\t{offset}\t{length}")
        data = ('\n'.join(lines) + '\n').encode('utf-8') if lines else b''
        compressed = gzip.compress(data)
        tmp_path = self.packs_dir / "index.gz.tmp"
        tmp_path.write_bytes(compressed)
        tmp_path.rename(self.packs_dir / "index.gz")
        self._index_dirty = False

    # -- block operations (pack-based) --

    def block_exists(self, h: str) -> bool:
        return h in self._pack_index

    def store_block(self, h: str, blob: bytes) -> None:
        """Append a pre-encrypted blob to the active pack file."""
        if h in self._pack_index:
            return  # dedup
        self._ensure_active_pack()
        offset = self._active_pack_size
        hash_bytes = h.encode('ascii')
        length_bytes = struct.pack('>I', len(blob))
        self._active_pack_fd.write(hash_bytes + length_bytes + blob)
        self._active_pack_fd.flush()
        self._active_pack_size += 64 + 4 + len(blob)
        self._pack_index[h] = (self._active_pack_id, offset, len(blob))
        self._index_dirty = True
        self.inode_count += 1

    def retrieve_block(self, h: str) -> bytes:
        """Return the encrypted blob for a given hash from its pack file."""
        pack_id, offset, length = self._pack_index[h]
        with open(self._pack_path(pack_id), 'rb') as f:
            f.seek(offset + 68)  # skip 64-byte hash + 4-byte length
            return f.read(length)

    # -- path helpers --

    @staticmethod
    def _path_hash(rel_path: str) -> str:
        """Return SHA-256 hex digest of a relative path (used for meta/ filenames)."""
        return hashlib.sha256(rel_path.encode("utf-8")).hexdigest()

    def _tree_entry_path(self, rel_path: str, snap_name: str) -> str:
        """Return the full path for a non-directory entry in tree/."""
        dirname = os.path.dirname(rel_path)
        basename = os.path.basename(rel_path)
        tree_name = f"{basename}-{snap_name}"
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

    # -- snapshot management --

    def snap_meta_dir(self, name: str) -> Path:
        return self.snapshots_dir / name / "meta"


    def snap_dir(self, name: str) -> Path:
        return self.snapshots_dir / name

    def snap_index_path(self, name: str) -> Path:
        """Return path to the snapshot index file."""
        return self.snap_dir(name) / "index"

    def snap_chunks_path(self, name: str) -> Path:
        """Return path to the snapshot chunks file."""
        return self.snap_dir(name) / "chunks"

    def _read_index_file(self, snap_name: str) -> str:
        """Read index file content, handling both plain and gzip-compressed formats."""
        index_path = self.snap_index_path(snap_name)
        if not index_path.exists():
            return ""
        raw = index_path.read_bytes()
        if raw[:2] == b'\x1f\x8b':
            return gzip.decompress(raw).decode("utf-8")
        return raw.decode("utf-8")

    def _compress_index(self, snap_name: str) -> None:
        """Compress the index file with gzip (in-place replacement)."""
        index_path = self.snap_index_path(snap_name)
        if not index_path.exists():
            return
        raw = index_path.read_bytes()
        if raw[:2] == b'\x1f\x8b':
            return  # Already compressed
        index_path.write_bytes(gzip.compress(raw))

    def _write_chunks_file(self, snap_name: str, chunk_hashes: set = None) -> None:
        """Write a gzip-compressed chunks file (one hash per line)."""
        if not chunk_hashes:
            return
        data = "\n".join(sorted(chunk_hashes)) + "\n"
        self.snap_chunks_path(snap_name).write_bytes(gzip.compress(data.encode()))

    def read_chunks_file(self, snap_name: str) -> set:
        """Read the chunks file and return a set of chunk hashes."""
        chunks_path = self.snap_chunks_path(snap_name)
        if chunks_path.exists():
            raw = chunks_path.read_bytes()
            if raw[:2] == b'\x1f\x8b':
                content = gzip.decompress(raw).decode()
            else:
                content = raw.decode()
            return {h for h in content.strip().split("\n") if h}
        return set()

    @staticmethod
    def _build_index_line(meta: dict, pack_mode: bool = False) -> str:
        """Build a tab-separated index line from a meta dict.

        Format: <ctime>\\t<type>\\t<mode>\\t<uid>\\t<gid>\\t<size>\\t<mtime>\\t<rel_path>[\\t<extra>]
        In pack_mode, appends: \\t<atime>\\t<acl>
        """
        entry_type = meta["type"]
        size = meta.get("size", 0) if entry_type == "file" else 0
        extra = ""
        if entry_type == "symlink":
            extra = f"\t{meta.get('symlink_target', '')}"
        elif entry_type == "hardlink":
            extra = f"\t{meta.get('link_target', '')}"
        elif entry_type in ("blockdev", "chardev"):
            extra = f"\t{meta.get('devmajor', 0)},{meta.get('devminor', 0)}"
        elif entry_type == "file":
            chunk_hashes = meta.get("chunk_hashes", [])
            if chunk_hashes:
                extra = f"\t{','.join(chunk_hashes)}"
        line = (f"{meta.get('ctime', 0)!r}\t{entry_type}\t{meta['mode']}\t"
                f"{meta['uid']}\t{meta['gid']}\t{size}\t{meta['mtime']!r}\t"
                f"{meta['rel_path']}{extra}")
        if pack_mode:
            if not extra:
                line += "\t"  # ensure extra field is present (even if empty)
            acl = meta.get('acl', '') or ''
            acl = acl.replace('\\', '\\\\').replace('\n', '\\n').replace('\t', '\\t')
            line += f"\t{meta.get('atime', 0)!r}\t{acl}"
        return line

    @staticmethod
    def _parse_index_line(line: str) -> Optional[dict]:
        """Parse a tab-separated index line into a dict.

        Returns dict with ctime, type, mode, uid, gid, size, mtime, rel_path,
        and optionally symlink_target, link_target, devmajor, devminor.
        Returns None for unparseable lines.
        """
        fields = line.split("\t")
        if len(fields) < 8:
            return None
        entry = {
            "ctime": float(fields[0]),
            "type": fields[1],
            "mode": int(fields[2]),
            "uid": int(fields[3]),
            "gid": int(fields[4]),
            "size": int(fields[5]),
            "mtime": float(fields[6]),
            "rel_path": fields[7],
        }
        extra = fields[8] if len(fields) > 8 else None
        if entry["type"] == "symlink" and extra is not None:
            entry["symlink_target"] = extra
        elif entry["type"] == "hardlink" and extra is not None:
            entry["link_target"] = extra
        elif entry["type"] in ("blockdev", "chardev") and extra is not None:
            parts = extra.split(",")
            entry["devmajor"] = int(parts[0])
            entry["devminor"] = int(parts[1]) if len(parts) > 1 else 0
        elif entry["type"] == "file" and extra:
            entry["chunk_hashes"] = extra.split(",")
        # Pack-mode extended fields: atime (field 9), acl (field 10)
        if len(fields) > 9:
            try:
                entry["atime"] = float(fields[9])
            except (ValueError, IndexError):
                entry["atime"] = 0.0
        if len(fields) > 10 and fields[10]:
            acl = fields[10].replace('\\n', '\n').replace('\\t', '\t').replace('\\\\', '\\')
            entry["acl"] = acl
        return entry

    def read_index(self, snap_name: str) -> dict:
        """Read the snapshot index and return {rel_path: index_line} dict.

        Returns the raw index line per path so callers can extract ctime
        or pass the line directly to link_entry.
        """
        content = self._read_index_file(snap_name)
        if not content:
            return {}
        result = {}
        for line in content.strip().split("\n"):
            if not line:
                continue
            fields = line.split("\t")
            if len(fields) >= 8:
                result[fields[7]] = line
            elif len(fields) == 2:
                # Legacy format: <ctime>\t<rel_path>
                result[fields[1]] = line
            else:
                result[fields[0]] = line
        return result

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
        # Create empty index file
        self.snap_index_path(name).write_text("")

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
                          stored_bytes: int = 0,
                          chunk_hashes: set = None) -> None:
        """Mark a snapshot as complete and write stats from internal counters."""
        self._compress_index(name)
        self._write_chunks_file(name, chunk_hashes)
        self._seal_active_pack()
        self._flush_pack_index()
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
            # Pack mode: only count, no filesystem writes
            if entry_type == "dir":
                self.inode_count += 1
            else:
                self.file_count += 1
                self.inode_count += 1

        # Append to index with full metadata for fast listing
        idx_meta = dict(meta)
        idx_meta["rel_path"] = rel_path
        pack_mode = (self.mode == "pack")
        with open(str(self.snap_index_path(snap_name)), "a") as fh:
            fh.write(self._build_index_line(idx_meta, pack_mode=pack_mode) + "\n")

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
            # Pack mode: O(1) lookup from cached parsed index
            index = self._get_parsed_snap_index(snap_name)
            parsed = index.get(rel_path)
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

    def link_entry(self, from_snap: str, to_snap: str, rel_path: str,
                   is_dir: bool = None, index_line: str = None,
                   meta: dict = None) -> bool:
        """Link an entry from one snapshot to another (for unchanged entries).

        For directories: hardlinks meta/ file and ensures tree/ dir exists.
        For non-dirs: hardlinks tree/ file only (no meta/ entry).
        Returns True on success, False if source doesn't exist.

        index_line: raw index line to copy into the new snapshot's index.
        meta:       dict to build index line from (used when metadata changed).
        If neither is given, a minimal fallback line is written.
        """
        if self.mode == "pack":
            # Pack mode: no hardlinks, only write index line
            self.file_count += 1
            if index_line is not None:
                line = index_line
            elif meta is not None:
                idx_meta = dict(meta)
                idx_meta["rel_path"] = rel_path
                pack_mode = True
                line = self._build_index_line(idx_meta, pack_mode=pack_mode)
            else:
                line = f"0\tunknown\t0\t0\t0\t0\t0\t{rel_path}"
            with open(str(self.snap_index_path(to_snap)), "a") as fh:
                fh.write(line + "\n")
            return True

        if is_dir is None:
            # Determine type from index_line if available
            if index_line:
                parsed = self._parse_index_line(index_line)
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

        # Append to index
        if index_line is not None:
            line = index_line
        elif meta is not None:
            idx_meta = dict(meta)
            idx_meta["rel_path"] = rel_path
            line = self._build_index_line(idx_meta)
        else:
            line = f"0\tunknown\t0\t0\t0\t0\t0\t{rel_path}"
        with open(str(self.snap_index_path(to_snap)), "a") as fh:
            fh.write(line + "\n")

        return True


    def link_unchanged_entries(self, from_snap: str, to_snap: str,
                              entries: list) -> int:
        """Server-side batch fast path: link multiple unchanged entries at once.

        entries is a list of (rel_path, is_dir, index_line) tuples.

        For each entry:
        - For dirs: ensures tree/ dir exists, hardlinks meta/ from previous snap
        - For non-dirs: hardlinks tree/ entry only (no meta/)
        - Appends index_line to new snapshot's index

        Returns the number of successfully linked entries.
        """
        index_path = str(self.snap_index_path(to_snap))
        linked = 0

        if self.mode == "pack":
            # Pack mode: no hardlinks, only write index lines
            index_buf = []
            for rel_path, is_dir, index_line in entries:
                self.file_count += 1
                index_buf.append(index_line)
                linked += 1
        else:
            tree_dir = str(self.tree_dir)
            index_buf = []
            for rel_path, is_dir, index_line in entries:
                if is_dir:
                    tree_dir_path = os.path.join(tree_dir, rel_path) if rel_path != "." else tree_dir
                    os.makedirs(tree_dir_path, exist_ok=True)
                    # Hardlink meta/ entry (dirs, bucketed)
                    src_meta = self._meta_entry_path(from_snap, rel_path)
                    dst_meta = self._meta_entry_path(to_snap, rel_path)
                    if not os.path.lexists(src_meta):
                        continue
                    os.makedirs(os.path.dirname(dst_meta), exist_ok=True)
                    os.link(src_meta, dst_meta)
                else:
                    # Hardlink tree/ entry only (no meta/ for non-dirs)
                    src_tree = self._tree_entry_path(rel_path, from_snap)
                    dst_tree = self._tree_entry_path(rel_path, to_snap)
                    if not os.path.lexists(src_tree):
                        continue
                    os.makedirs(os.path.dirname(dst_tree), exist_ok=True)
                    os.link(src_tree, dst_tree)

                self.file_count += 1
                index_buf.append(index_line)
                linked += 1

        # Batch-write all index lines at once
        if index_buf:
            with open(index_path, "a") as fh:
                fh.write("\n".join(index_buf) + "\n")

        return linked


    def list_entries(self, snap_name: str, filter_path: Optional[str] = None,
                     full: bool = False) -> list:
        """Read snapshot index and return entry dicts with metadata.

        When full=False (default), returns data from the index only — no
        filesystem access needed.  When full=True, also reads meta/ files
        for chunk_hashes and ACLs (needed for restore).

        Returns list of dicts with keys:
            rel_path:       relative path (adjusted for filter_path)
            type:           "file" | "dir" | "symlink" | "hardlink" | ...
            mode, uid, gid, mtime: from index
            symlink_target: str or None
            link_target:    str (only for type=hardlink)
            size:           int (for files)
          When full=True, additionally:
            acl:            str or None
            chunk_hashes:   list[str] (for files)
        """
        content = self._read_index_file(snap_name)
        if not content:
            raise FileNotFoundError(f"Snapshot not found: {snap_name}")

        if filter_path is not None:
            filter_path = filter_path.strip("/")

        index_lines = content.strip().split("\n")
        meta_dir = str(self.snap_meta_dir(snap_name))

        entries = []
        found_filter = False
        for line in index_lines:
            if not line:
                continue

            parsed = self._parse_index_line(line)
            if parsed is None:
                continue

            rel_path = parsed["rel_path"]

            # Apply filter
            if filter_path is not None:
                if rel_path != filter_path and not rel_path.startswith(filter_path + "/"):
                    continue
                found_filter = True
                display_rel = os.path.relpath(rel_path, filter_path) if rel_path != filter_path else "."
            else:
                display_rel = rel_path

            entry = {
                "rel_path": display_rel,
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
                if self.mode == "pack":
                    # Pack mode: all metadata comes from the index
                    entry["atime"] = parsed.get("atime", 0.0)
                    entry["acl"] = parsed.get("acl")
                    if parsed["type"] == "file":
                        entry["chunk_hashes"] = parsed.get("chunk_hashes", [])
                    else:
                        entry["chunk_hashes"] = []
                else:
                    if parsed["type"] == "dir":
                        # Dirs use meta/ (bucketed)
                        entry_path = self._meta_entry_path(snap_name, rel_path)
                    else:
                        # Non-dirs read directly from tree/
                        entry_path = self._tree_entry_path(rel_path, snap_name)
                    st = os.lstat(entry_path)
                    entry["atime"] = st.st_atime
                    entry["acl"] = _get_acl_text(entry_path)
                    if parsed["type"] == "file":
                        lines = self._read_gz(entry_path).strip().split("\n")
                        entry["chunk_hashes"] = [h for h in lines[2:] if h] if len(lines) > 2 else []
                    else:
                        entry["chunk_hashes"] = []

            entries.append(entry)

        if filter_path is not None and not found_filter:
            raise FileNotFoundError(
                f"Path '{filter_path}' not found in snapshot '{snap_name}'"
            )

        # Sort by rel_path for consistent output (dirs before their contents)
        entries.sort(key=lambda e: e["rel_path"])
        return entries

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
        """Remove a snapshot's tree/ entries and snapshot directory (no GC)."""
        snap_dir = self.snap_dir(snap_name)
        if not snap_dir.exists():
            raise FileNotFoundError(f"Snapshot not found: {snap_name}")

        # Remove tree/ entries for non-dir entries using the index file
        if self.mode != "pack":
            content = self._read_index_file(snap_name)
            if content:
                for line in content.strip().split("\n"):
                    if not line:
                        continue
                    parsed = self._parse_index_line(line)
                    if parsed is None or parsed["type"] == "dir":
                        continue
                    rel_path = parsed["rel_path"]
                    tree_path = self._tree_entry_path(rel_path, snap_name)
                    try:
                        os.unlink(tree_path)
                    except OSError:
                        pass
                    # Remove parent dirs if empty, up to tree_dir
                    parent = os.path.dirname(tree_path)
                    while parent != str(self.tree_dir):
                        try:
                            os.rmdir(parent)
                        except OSError:
                            break
                        parent = os.path.dirname(parent)

        # Remove snapshot directory (meta/ + complete + running + index)
        shutil.rmtree(snap_dir)

    def delete_snapshot(self, snap_name: str) -> int:
        """Delete a snapshot and run GC.  Returns number of orphaned blocks removed."""
        self.lock_repo()
        self.load_pack_index()
        try:
            return self._delete_snapshot_locked(snap_name)
        finally:
            self.unlock_repo()

    def _delete_snapshot_locked(self, snap_name: str) -> int:
        """Internal delete — caller must hold the lock."""
        logger.info("Deleting snapshot '%s' ...", snap_name)
        dead_hashes = self.read_chunks_file(snap_name)
        self._remove_snapshot(snap_name)

        if not dead_hashes:
            logger.info("GC done: 0 orphaned blocks removed")
            return 0

        # Collect live hashes from all remaining snapshots
        live_hashes = set()
        if self.snapshots_dir.exists():
            for snap in self.snapshots_dir.iterdir():
                if not snap.is_dir():
                    continue
                live_hashes |= self.read_chunks_file(snap.name)

        orphaned = dead_hashes - live_hashes
        if not orphaned:
            logger.info("GC done: 0 orphaned blocks removed")
            return 0

        self._gc_remove_from_index(orphaned)
        logger.info("GC done: %d orphaned blocks removed", len(orphaned))
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
        dead_hashes = set()
        for name, _ in entries:
            if name not in keep:
                if dry_run:
                    logger.info("Retention: would delete snapshot '%s'", name)
                else:
                    logger.info("Retention: deleting snapshot '%s'", name)
                    dead_hashes |= self.read_chunks_file(name)
                    self._remove_snapshot(name)
                deleted.append(name)

        if deleted and not dry_run and dead_hashes:
            # Collect live hashes from remaining snapshots
            live_hashes = set()
            if self.snapshots_dir.exists():
                for snap in self.snapshots_dir.iterdir():
                    if not snap.is_dir():
                        continue
                    live_hashes |= self.read_chunks_file(snap.name)
            orphaned = dead_hashes - live_hashes
            if orphaned:
                self._gc_remove_from_index(orphaned)
                logger.info("Retention GC: %d orphaned blocks removed", len(orphaned))

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
        live_hashes = set()
        if self.snapshots_dir.exists():
            for snap in self.snapshots_dir.iterdir():
                if not snap.is_dir():
                    continue
                live_hashes |= self.read_chunks_file(snap.name)

        orphaned = set(self._pack_index.keys()) - live_hashes
        if not orphaned:
            return 0

        self._gc_remove_from_index(orphaned)
        return len(orphaned)

    def _gc_remove_from_index(self, orphaned: set) -> None:
        """Remove orphaned hashes from pack index, delete fully empty packs."""
        # Build pack -> hashes mapping
        pack_hashes = {}
        for h, (pid, _, _) in self._pack_index.items():
            pack_hashes.setdefault(pid, set()).add(h)

        for h in orphaned:
            del self._pack_index[h]

        # Delete fully empty pack files + empty bucket dirs
        for pid, hashes in pack_hashes.items():
            if hashes.issubset(orphaned):
                p = self._pack_path(pid)
                p.unlink(missing_ok=True)
                try:
                    p.parent.rmdir()
                except OSError:
                    pass

        self._index_dirty = True
        self._flush_pack_index()

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
        for h, (pid, offset, length) in self._pack_index.items():
            live_by_pack.setdefault(pid, []).append((h, offset, length))

        saved = 0
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
                    self._pack_index[h] = (pid, new_offset, length)
                    new_offset += 64 + 4 + length
            tmp_path.rename(pack_path)
            saved += pack_size - new_offset

        if saved > 0:
            self._index_dirty = True
            self._flush_pack_index()
        return saved

    def rebuild_pack_index(self) -> int:
        """Rebuild index.gz by scanning all pack-*.dat files. Returns entry count."""
        self.lock_repo()
        self.load_pack_index()
        try:
            return self._rebuild_pack_index_locked()
        finally:
            self.unlock_repo()

    def _rebuild_pack_index_locked(self) -> int:
        self._pack_index = {}
        count = 0
        if not self.packs_dir.exists():
            self._index_dirty = True
            self._flush_pack_index()
            return 0

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
                        self._pack_index[h] = (pid, offset, blob_len)
                        count += 1
                        offset += 68 + blob_len

        self._index_dirty = True
        self._flush_pack_index()
        return count


# ---------------------------------------------------------------------------
# BackupClient — crypto + file I/O, no storage knowledge
# ---------------------------------------------------------------------------

class BackupClient:
    """Handles encryption/decryption and filesystem operations.

    The client never touches the storage layout directly.  All storage
    operations go through the server interface.
    """

    def __init__(self, server: object, password: str = None, key: bytes = None,
                 compress: bool = True):
        self.server = server
        self.compress = compress
        if key is not None:
            if len(key) != KEY_SIZE:
                raise ValueError(f"Key must be {KEY_SIZE} bytes, got {len(key)}")
            self.key = key
        elif password is not None:
            salt = server.get_salt()
            self.key = derive_key(password, salt)
        #else:
        #    raise ValueError("Either password or key must be provided")

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

    def collect_entry(self, fpath: str, source: str) -> Optional[dict]:
        """Collect metadata for a filesystem entry.

        Returns a dict suitable for server.write_entry(), or None for
        unsupported file types (devices, fifos, sockets).
        """
        st = os.lstat(fpath)
        rel = os.path.relpath(fpath, source)
        mode = st.st_mode

        meta = {
            "path": rel,
            "mode": mode,
            "uid": st.st_uid,
            "gid": st.st_gid,
            "atime": st.st_atime,
            "mtime": st.st_mtime,
        }

        if stat.S_ISDIR(mode):
            meta["type"] = "dir"
            meta["acl"] = _get_acl_text(fpath)
        elif stat.S_ISLNK(mode):
            meta["type"] = "symlink"
            meta["symlink_target"] = os.readlink(fpath)
        elif stat.S_ISREG(mode):
            meta["type"] = "file"
            meta["size"] = st.st_size
            meta["acl"] = _get_acl_text(fpath)
            meta["chunk_hashes"] = []  # filled during backup
        else:
            logger.debug("Skipping special file %s", fpath)
            return None

        return meta

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
            prev_index = {}
            snaps = self.server.list_snapshots()
            for s in reversed(snaps):
                if s["complete"]:
                    prev_snap = s["name"]
                    prev_index = self.server.read_index(prev_snap)
                    break

            self.server.create_snapshot(snap_name)
            self.server.set_running(snap_name)

        repo_mode = self.server.get_mode()

        total_bytes = 0
        stored_bytes = 0
        all_chunk_hashes = set()
        file_count = 0
        dedup_blocks = 0
        new_blocks = 0
        skipped_files = 0
        unchanged_entries = []  # (rel_path, is_dir, index_line) for batch link

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
            prev_line = prev_index.get(rel) if prev_snap else None
            if prev_line is not None:
                try:
                    prev_ctime = float(prev_line.split("\t", 1)[0])
                except (ValueError, IndexError):
                    prev_ctime = None
            else:
                prev_ctime = None
            if prev_ctime is not None and prev_ctime == st.st_ctime:
                is_dir = (entry_type == "dir")
                if entry_type == "file":
                    if st.st_nlink > 1:
                        seen_inodes[ino_key] = rel
                    file_count += 1
                    skipped_files += 1
                    # Extract chunk hashes from previous index line
                    prev_fields = prev_line.split("\t")
                    if len(prev_fields) >= 9 and prev_fields[1] == "file" and prev_fields[8]:
                        all_chunk_hashes.update(prev_fields[8].split(","))
                unchanged_entries.append((rel, is_dir, prev_line))
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
                        prev = self.server.get_entry_full(prev_snap, rel)
                        cur_acl = meta["acl"]
                        if (prev
                                and prev["uid"] == st.st_uid
                                and prev["gid"] == st.st_gid
                                and stat.S_IMODE(prev["mode"]) == stat.S_IMODE(mode)
                                and prev.get("mtime") == st.st_mtime
                                and prev["acl"] == cur_acl):
                            linked = self.server.link_entry(prev_snap, snap_name, rel,
                                                            is_dir=True, meta=meta)
                    if not linked:
                        self.server.write_entry(snap_name, rel, meta)
                    dir_entries.append((rel, meta))

                elif entry_type == "file":
                    if st.st_nlink > 1:
                        seen_inodes[ino_key] = rel
                    file_count += 1
                    chunk_hashes = []

                    # mtime-based skip: reuse data entry + refs from previous snapshot
                    skipped = False
                    if prev_snap:
                        prev = self.server.get_entry_full(prev_snap, rel)
                        if (prev and "file_size" in prev
                                and prev["file_mtime"] == st.st_mtime
                                and prev["file_size"] == st.st_size):
                            chunk_hashes = prev["chunk_hashes"]
                            all_chunk_hashes.update(chunk_hashes)
                            # Link data entry if metadata unchanged, else write new
                            cur_acl = _get_acl_text(fpath)
                            if (prev["uid"] == st.st_uid
                                    and prev["gid"] == st.st_gid
                                    and stat.S_IMODE(prev["mode"]) == stat.S_IMODE(mode)
                                    and prev["acl"] == cur_acl):
                                self.server.link_entry(prev_snap, snap_name, rel,
                                                        is_dir=False, meta={
                                                            "type": "file", "mode": mode,
                                                            "uid": st.st_uid, "gid": st.st_gid,
                                                            "size": st.st_size, "mtime": st.st_mtime,
                                                            "ctime": st.st_ctime,
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
                                self.server.write_entry(snap_name, rel, meta)
                                if repo_mode != "pack":
                                    self.server.set_entry_metadata(snap_name, rel, meta)
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
                                all_chunk_hashes.add(h)

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
                        self.server.write_entry(snap_name, rel, meta)
                        if repo_mode != "pack":
                            self.server.set_entry_metadata(snap_name, rel, meta)

                elif entry_type == "symlink":
                    prev = self.server.get_entry_full(prev_snap, rel) if prev_snap else None
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
                            and self.server.link_entry(prev_snap, snap_name, rel,
                                                        is_dir=False, meta=meta)):
                        pass
                    else:
                        self.server.write_entry(snap_name, rel, meta)
                        if repo_mode != "pack":
                            self.server.set_entry_metadata(snap_name, rel, meta)

                elif entry_type == "hardlink":
                    prev = self.server.get_entry_full(prev_snap, rel) if prev_snap else None
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
                            and self.server.link_entry(prev_snap, snap_name, rel,
                                                        is_dir=False, meta=meta)):
                        pass
                    else:
                        self.server.write_entry(snap_name, rel, meta)
                        if repo_mode != "pack":
                            self.server.set_entry_metadata(snap_name, rel, meta)
                    continue

                elif entry_type in ("blockdev", "chardev"):
                    prev = self.server.get_entry_full(prev_snap, rel) if prev_snap else None
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
                            and self.server.link_entry(prev_snap, snap_name, rel,
                                                        is_dir=False, meta=meta)):
                        pass
                    else:
                        self.server.write_entry(snap_name, rel, meta)
                        if repo_mode != "pack":
                            self.server.set_entry_metadata(snap_name, rel, meta)

                elif entry_type in ("fifo", "socket"):
                    prev = self.server.get_entry_full(prev_snap, rel) if prev_snap else None
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
                            and self.server.link_entry(prev_snap, snap_name, rel,
                                                        is_dir=False, meta=meta)):
                        pass
                    else:
                        self.server.write_entry(snap_name, rel, meta)
                        if repo_mode != "pack":
                            self.server.set_entry_metadata(snap_name, rel, meta)

            except (PermissionError, OSError) as exc:
                logger.warning("Skipping %s: %s", fpath, exc)

        if dry_run:
            return snap_name

        # Batch-link all ctime-unchanged entries in one roundtrip
        if unchanged_entries:
            if repo_mode == "tree":
                logger.info("Linking unchanged entries: %d", len(unchanged_entries))
            self.server.link_unchanged_entries(prev_snap, snap_name,
                                               unchanged_entries)

        # Deferred: set directory metadata deepest-first so mtime isn't
        # clobbered by later file creation in tree/.
        if dir_entries and repo_mode != "pack":
            logger.info("Processing changed directories: %d", len(dir_entries))
            self.server.set_dirs_metadata(snap_name, dir_entries)

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
        self.server.finalize_snapshot(snap_name,
                                      total_bytes=total_bytes,
                                      stored_bytes=stored_bytes,
                                      chunk_hashes=all_chunk_hashes)
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
        entry_list = self.server.list_entries(snap_name, filter_path, full=True)

        if not entry_list:
            logger.warning("No entries found")
            return

        # Determine if this is a single-file restore
        single_file = (len(entry_list) == 1 and entry_list[0]["type"] != "dir")

        restored = []  # (dst_path, entry) for deferred metadata

        for entry in entry_list:
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
                    os.makedirs(os.path.dirname(dst_entry), exist_ok=True)
                    link_target = entry["link_target"]
                    if filter_path is not None:
                        fp = filter_path.strip("/") + "/"
                        if link_target.startswith(fp):
                            link_target = link_target[len(fp):]
                        elif link_target == filter_path.strip("/"):
                            link_target = "."
                        else:
                            logger.warning("Skipping hardlink %s: target %s outside restored path",
                                           entry["rel_path"], link_target)
                            continue
                    link_src = os.path.join(dest, link_target)
                    if os.path.lexists(dst_entry):
                        os.unlink(dst_entry)
                    os.link(link_src, dst_entry)

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

    def list_contents(self, snap_name: str,
                      filter_path: Optional[str] = None) -> list:
        """Return a list of dicts describing the contents of a snapshot.

        Each dict has keys: type, rel_path, uid, gid, size, and
        optionally symlink_target / link_target.
        """
        return self.server.list_entries(snap_name, filter_path)

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
    content = server._read_index_file(snap_name)
    if not content:
        raise FileNotFoundError(f"Snapshot not found: {snap_name}")

    errors = 0
    checked = 0

    for line in content.strip().split("\n"):
        if not line:
            continue
        parsed = server._parse_index_line(line)
        if parsed is None or parsed["type"] != "file":
            continue

        rel_path = parsed["rel_path"]
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
