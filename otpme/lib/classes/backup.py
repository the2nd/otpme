# -*- coding: utf-8 -*-
# NOTE: This module was written by claude code!
import os
import stat
import zlib
import shutil
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
   ←──── receives encrypted blob ──      add_ref(name, hash)
   AES-GCM decryption                   list_entries(name) → [entry...]
   zlib decompression                    list_snapshots() → [...]
   File writing + metadata restore       delete_snapshot(name)
                                         gc_orphaned_blocks()

  The server never sees plaintext.  The client knows nothing about storage layout.

Storage layout
==============

  backup_dir/
  ├── key.salt                   # PBKDF2 salt (600 000 iterations → AES-256 key)
  ├── objects/                   # Content-addressable encrypted block store
  │   └── XX/                   #   first 2 hex chars of SHA-256
  │       └── <sha256>          #   flag(1) + nonce(12) + AES-GCM(zlib(data)) + tag(16)
  └── snapshots/
      └── <name>/
          ├── data/             # *Real* filesystem tree — permissions, ACLs,
          │   ├── etc/          #   ownership, timestamps are set on the actual
          │   │   └── cfg       #   files/dirs.  File content = chunk-hash list.
          │   └── home/
          │       └── user/
          │           └── doc
          └── refs/             # Hardlinks into objects/ — reference counting!
              ├── <hash1> ──→ objects/a1/<hash1>
              └── <hash2> ──→ objects/b3/<hash2>

File content format (regular files in data/)
============================================

  <size> <mtime>                 ← first line: decimal size + original mtime
  <sha256_chunk_hash_1>          ← one hash per line, in order
  <sha256_chunk_hash_2>
  ...

Snapshot deletion & garbage collection
======================================

  1. shutil.rmtree(snapshots/<name>)   — removes data/ AND refs/ (hardlinks)
  2. Scan objects/:  any chunk with st_nlink == 1  → orphaned → delete

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

def _get_acl_text(path: str) -> Optional[str]:
    try:
        acl = posix1e.ACL(file=path)
        return acl.to_any_text(options=posix1e.TEXT_NUMERIC_IDS).decode()
    except (OSError, IOError):
        return None

def _set_acl_text(path: str, acl_text: str) -> None:
    try:
        posix1e.ACL(text=acl_text).applyto(path)
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
        self.objects_dir   = self.root / "objects"
        self.snapshots_dir = self.root / "snapshots"
        self.salt_file     = self.root / "key.salt"
        self.file_count    = 0
        self.inode_count   = 0
        self.ref_count     = 0

    def init_repository(self):
        """Create the backup directory structure if it doesn't exist."""
        self.root.mkdir(parents=True, exist_ok=True)
        self.objects_dir.mkdir(exist_ok=True)
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

    # -- block operations --

    def _block_path(self, h: str) -> Path:
        return self.objects_dir / h[:2] / h

    def block_exists(self, h: str) -> bool:
        return self._block_path(h).exists()

    def store_block(self, h: str, blob: bytes) -> None:
        """Store a pre-encrypted blob under its plaintext hash."""
        p = self._block_path(h)
        if not p.exists():
            p.parent.mkdir(exist_ok=True)
            p.write_bytes(blob)
            p.chmod(0o644)
            self.inode_count += 1

    def retrieve_block(self, h: str) -> bytes:
        """Return the encrypted blob for a given hash (no decryption)."""
        return self._block_path(h).read_bytes()

    # -- snapshot management --

    def snap_data_dir(self, name: str) -> Path:
        return self.snapshots_dir / name / "data"

    def snap_refs_dir(self, name: str) -> Path:
        return self.snapshots_dir / name / "refs"

    def snap_dir(self, name: str) -> Path:
        return self.snapshots_dir / name

    def create_snapshot(self, name: str) -> None:
        """Create data/ and refs/ directories for a new snapshot."""
        self.file_count = 0
        self.inode_count = 0
        self.ref_count = 0
        self.start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.snap_data_dir(name).mkdir(parents=True, exist_ok=True)
        self.snap_refs_dir(name).mkdir(parents=True, exist_ok=True)

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

    def finalize_snapshot(self, name: str) -> None:
        """Mark a snapshot as complete and write stats from internal counters."""
        self.clear_running(name)
        marker = self.snap_dir(name) / "complete"
        end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        start_time = getattr(self, 'start_time', end_time)
        stats = {
            "files": self.file_count,
            "inodes": self.inode_count,
            "refs": self.ref_count,
            "start_time": start_time,
            "end_time": end_time,
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
        """Create a single entry (file/dir/symlink) in the snapshot data/ tree.

        Only creates the filesystem object — does NOT apply metadata.
        Call set_entry_metadata() separately (deepest-first) to avoid
        directory mtime clobbering.

        meta dict keys:
            type:           "file" | "dir" | "symlink"
            symlink_target: str (only for type=symlink)
            size:           int (original file size, only for type=file)
            chunk_hashes:   list[str] (only for type=file)
        """
        data_dir = self.snap_data_dir(snap_name)
        dst = os.path.join(str(data_dir), rel_path) if rel_path != "." else str(data_dir)
        entry_type = meta["type"]

        if entry_type == "dir":
            os.makedirs(dst, exist_ok=True)

        elif entry_type == "symlink":
            if os.path.lexists(dst):
                os.unlink(dst)
            os.symlink(meta["symlink_target"], dst)

        elif entry_type == "hardlink":
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(dst, "w") as fh:
                fh.write(f"HARDLINK\n{meta['link_target']}\n")

        elif entry_type in ("blockdev", "chardev"):
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(dst, "w") as fh:
                fh.write(f"{entry_type.upper()}\n{meta['devmajor']} {meta['devminor']}\n")

        elif entry_type == "fifo":
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(dst, "w") as fh:
                fh.write("FIFO\n")

        elif entry_type == "socket":
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(dst, "w") as fh:
                fh.write("SOCKET\n")

        elif entry_type == "file":
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            content = f"{meta['size']} {meta['mtime']!r}\n"
            chunk_hashes = meta.get("chunk_hashes", [])
            content += "\n".join(chunk_hashes)
            if chunk_hashes:
                content += "\n"
            with open(dst, "w") as fh:
                fh.write(content)

        if entry_type == "dir":
            self.inode_count += 1
        else:
            self.file_count += 1
            self.inode_count += 1

    def set_entry_metadata(self, snap_name: str, rel_path: str, meta: dict) -> None:
        """Apply ownership, permissions, ACLs, and timestamps to a data/ entry.

        meta dict keys:
            type:           "file" | "dir" | "symlink"
            mode:           int (file mode bits)
            uid, gid:       int
            atime, mtime:   float
            acl:            str or None
        """
        data_dir = self.snap_data_dir(snap_name)
        dst = os.path.join(str(data_dir), rel_path) if rel_path != "." else str(data_dir)
        is_link = (meta["type"] == "symlink")

        try:
            os.lchown(dst, meta["uid"], meta["gid"])
        except (PermissionError, OSError) as exc:
            logger.debug("lchown %s: %s", dst, exc)

        if not is_link:
            try:
                os.chmod(dst, stat.S_IMODE(meta["mode"]))
            except (PermissionError, OSError) as exc:
                logger.debug("chmod %s: %s", dst, exc)
            if meta.get("acl"):
                _set_acl_text(dst, meta["acl"])

        try:
            os.utime(dst, (meta["atime"], meta["mtime"]), follow_symlinks=False)
        except (OSError, AttributeError):
            pass

    def get_file_entry(self, snap_name: str, rel_path: str) -> Optional[dict]:
        """Read a single file entry from an existing snapshot.

        Returns {"mtime": float, "size": int, "chunk_hashes": [str]} or None.
        """
        data_dir = self.snap_data_dir(snap_name)
        dst = os.path.join(str(data_dir), rel_path)
        try:
            st = os.lstat(dst)
        except OSError:
            return None
        if not stat.S_ISREG(st.st_mode):
            return None
        with open(dst, "r") as fh:
            lines = fh.read().strip().split("\n")
        if not lines:
            return None
        header = lines[0].split()
        size = int(header[0])
        # mtime stored in header since format v2; fall back to lstat
        mtime = float(header[1]) if len(header) > 1 else st.st_mtime
        chunk_hashes = [h for h in lines[1:] if h] if len(lines) > 1 else []
        return {
            "mtime": mtime,
            "size": size,
            "chunk_hashes": chunk_hashes,
        }

    def get_entry_metadata(self, snap_name: str, rel_path: str) -> Optional[dict]:
        """Read metadata (mode, uid, gid, acl) of a data/ entry.

        Returns dict with mode, uid, gid, acl keys, or None.
        """
        data_dir = self.snap_data_dir(snap_name)
        dst = os.path.join(str(data_dir), rel_path)
        try:
            st = os.lstat(dst)
        except OSError:
            return None
        acl = _get_acl_text(dst) if not stat.S_ISLNK(st.st_mode) else None
        return {
            "mode": st.st_mode,
            "uid": st.st_uid,
            "gid": st.st_gid,
            "acl": acl,
        }

    def link_entry(self, from_snap: str, to_snap: str, rel_path: str) -> bool:
        """Hardlink a data/ entry from one snapshot to another.

        Returns True if the link was created, False if the source doesn't exist.
        Parent directories in the target are created as needed.
        """
        src = os.path.join(str(self.snap_data_dir(from_snap)), rel_path)
        dst = os.path.join(str(self.snap_data_dir(to_snap)), rel_path)
        if not os.path.lexists(src):
            return False
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        os.link(src, dst)
        self.file_count += 1
        return True

    def copy_refs(self, from_snap: str, to_snap: str, chunk_hashes: list) -> None:
        """Copy refs from one snapshot to another for the given chunk hashes."""
        for h in chunk_hashes:
            self.add_ref(to_snap, h)

    def add_ref(self, snap_name: str, chunk_hash: str) -> None:
        """Create a hardlink in refs/ pointing to the object block."""
        refs_dir = self.snap_refs_dir(snap_name)
        ref_path = refs_dir / chunk_hash
        if ref_path.exists():
            return
        obj_path = self._block_path(chunk_hash)
        os.link(obj_path, ref_path)
        self.ref_count += 1

    def list_entries(self, snap_name: str, filter_path: Optional[str] = None) -> list:
        """Walk snapshot data/ and yield entry dicts with metadata.

        Returns list of dicts with keys:
            src_path:       absolute path in data/ tree
            rel_path:       relative path within data/
            type:           "file" | "dir" | "symlink" | "hardlink"
            mode, uid, gid, atime, mtime: from lstat
            acl:            str or None
            symlink_target: str or None
            link_target:    str (only for type=hardlink, rel_path of link source)
            size:           int (from first line of chunk-hash file, for files)
            chunk_hashes:   list[str] (for files)
        """
        data_dir = self.snap_data_dir(snap_name)
        if not data_dir.exists():
            raise FileNotFoundError(f"Snapshot not found: {snap_name}")

        if filter_path is not None:
            filter_path = filter_path.strip("/")
            walk_root = os.path.join(str(data_dir), filter_path)
            if not os.path.lexists(walk_root):
                raise FileNotFoundError(
                    f"Path '{filter_path}' not found in snapshot '{snap_name}'"
                )
        else:
            walk_root = str(data_dir)

        entries = []
        for src_entry, st in _walk(walk_root):
            rel = os.path.relpath(src_entry, walk_root)
            mode = st.st_mode
            entry = {
                "src_path": src_entry,
                "rel_path": rel,
                "mode": mode,
                "uid": st.st_uid,
                "gid": st.st_gid,
                "atime": st.st_atime,
                "mtime": st.st_mtime,
            }

            if stat.S_ISDIR(mode):
                entry["type"] = "dir"
                entry["acl"] = _get_acl_text(src_entry)
                entry["symlink_target"] = None
                entry["size"] = 0
                entry["chunk_hashes"] = []

            elif stat.S_ISLNK(mode):
                entry["type"] = "symlink"
                entry["symlink_target"] = os.readlink(src_entry)
                entry["acl"] = None
                entry["size"] = 0
                entry["chunk_hashes"] = []

            elif stat.S_ISREG(mode):
                # Read file content to determine type (file vs hardlink marker)
                with open(src_entry, "r") as fh:
                    lines = fh.read().strip().split("\n")
                marker = lines[0] if lines else ""
                if marker == "HARDLINK":
                    entry["type"] = "hardlink"
                    entry["link_target"] = lines[1] if len(lines) > 1 else ""
                    entry["acl"] = None
                    entry["symlink_target"] = None
                    entry["size"] = 0
                    entry["chunk_hashes"] = []
                elif marker in ("BLOCKDEV", "CHARDEV"):
                    entry["type"] = marker.lower()
                    majmin = lines[1].split() if len(lines) > 1 else ["0", "0"]
                    entry["devmajor"] = int(majmin[0])
                    entry["devminor"] = int(majmin[1])
                    entry["acl"] = None
                    entry["symlink_target"] = None
                    entry["size"] = 0
                    entry["chunk_hashes"] = []
                elif marker in ("FIFO", "SOCKET"):
                    entry["type"] = marker.lower()
                    entry["acl"] = None
                    entry["symlink_target"] = None
                    entry["size"] = 0
                    entry["chunk_hashes"] = []
                else:
                    entry["type"] = "file"
                    entry["acl"] = _get_acl_text(src_entry)
                    entry["symlink_target"] = None
                    header = lines[0].split() if lines else []
                    entry["size"] = int(header[0]) if header else 0
                    entry["chunk_hashes"] = [h for h in lines[1:] if h] if len(lines) > 1 else []

            else:
                continue

            entries.append(entry)

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
            ref_count = stats.get("refs", 0)
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

            result.append({
                "name": snap.name,
                "files": file_count,
                "inodes": inode_count,
                "refs": ref_count,
                "created": ts,
                "start_time": start_time,
                "end_time": end_time,
                "duration": duration,
                "complete": complete,
                "running": running,
                "running_since": running_since,
            })
        return result

    def delete_snapshot(self, snap_name: str) -> int:
        """Delete a snapshot and run GC.  Returns number of orphaned blocks removed."""
        snap_dir = self.snap_dir(snap_name)
        if not snap_dir.exists():
            raise FileNotFoundError(f"Snapshot not found: {snap_name}")

        logger.info("Deleting snapshot '%s' ...", snap_name)
        shutil.rmtree(snap_dir)
        logger.info("Snapshot removed.  Running garbage collection ...")

        removed = self.gc_orphaned_blocks()
        logger.info("GC done: %d orphaned blocks removed", removed)
        return removed

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

    def apply_retention(self, daily: int = 0, weekly: int = 0, monthly: int = 0, dry_run: bool = False) -> list:
        """Delete snapshots that fall outside the retention policy.

        Keeps the *newest* snapshot per calendar day / ISO week / month,
        then retains at most ``daily`` daily, ``weekly`` weekly, and
        ``monthly`` monthly snapshots.  Any snapshot not covered by at
        least one retention bucket is deleted.

        Returns the list of deleted snapshot names.
        """
        snaps = self.list_snapshots()
        if not snaps:
            return []

        # Build (name, datetime) pairs sorted newest-first.
        # Parse date from the snapshot name itself.
        entries = []
        for s in snaps:
            name = s["name"]
            dt = self._parse_snap_date(name)
            if dt is None:
                logger.warning("Cannot parse date from snapshot name '%s', keeping it", name)
                continue
            entries.append((name, dt))
        entries.sort(key=lambda e: e[1], reverse=True)

        # For each bucket type, group snapshots by period,
        # then keep all snapshots in the N most recent periods.
        def _pick(key_func, keep_count):
            """Return set of snapshot names to keep."""
            if keep_count <= 0:
                return set()
            groups = {}
            for name, dt in entries:
                k = key_func(dt)
                if k not in groups:
                    groups[k] = []
                groups[k].append(name)
            # groups is ordered newest-first because entries are
            kept_periods = list(groups.keys())[:keep_count]
            result = set()
            for k in kept_periods:
                result.update(groups[k])
            return result

        keep = set()
        keep |= _pick(lambda dt: dt.date(), daily)
        keep |= _pick(lambda dt: dt.isocalendar()[:2], weekly)
        keep |= _pick(lambda dt: (dt.year, dt.month), monthly)

        deleted = []
        for name, _ in entries:
            if name not in keep:
                if dry_run:
                    logger.info("Retention: would delete snapshot '%s'", name)
                else:
                    logger.info("Retention: deleting snapshot '%s'", name)
                    snap_dir = self.snap_dir(name)
                    if snap_dir.exists():
                        shutil.rmtree(snap_dir)
                deleted.append(name)

        if deleted and not dry_run:
            removed = self.gc_orphaned_blocks()
            logger.info("Retention GC: %d orphaned blocks removed", removed)

        return deleted

    def gc_orphaned_blocks(self) -> int:
        """Delete blocks in objects/ whose link count is 1 (no snapshot refs)."""
        removed = 0
        for prefix_dir in self.objects_dir.iterdir():
            if not prefix_dir.is_dir():
                continue
            for block_file in prefix_dir.iterdir():
                if block_file.stat().st_nlink == 1:
                    block_file.unlink()
                    removed += 1
            # remove empty prefix dir
            try:
                prefix_dir.rmdir()
            except OSError:
                pass
        return removed


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
            # Determine previous complete snapshot for mtime-based skip
            prev_snap = None
            snaps = self.server.list_snapshots()
            for s in reversed(snaps):
                if s["complete"]:
                    prev_snap = s["name"]
                    break

            self.server.create_snapshot(snap_name)
            self.server.set_running(snap_name)

        total_bytes = 0
        stored_bytes = 0
        file_count = 0
        dedup_blocks = 0
        new_blocks = 0
        skipped_files = 0

        # Two passes:
        #   pass 1 — create entries in data/ via server + store blocks
        #   pass 2 — set metadata via server (deepest first so dir mtime isn't clobbered)

        entries = []  # list of (rel_path, meta) for deferred metadata pass
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

            try:
                if entry_type == "dir":
                    meta = {
                        "type": "dir",
                        "mode": mode,
                        "uid": st.st_uid, "gid": st.st_gid,
                        "atime": st.st_atime, "mtime": st.st_mtime,
                        "acl": _get_acl_text(fpath),
                    }
                    self.server.write_entry(snap_name, rel, meta)
                    entries.append((rel, meta))

                elif entry_type == "file":
                    if st.st_nlink > 1:
                        seen_inodes[ino_key] = rel
                    file_count += 1
                    chunk_hashes = []

                    # mtime-based skip: reuse data entry + refs from previous snapshot
                    skipped = False
                    if prev_snap:
                        prev_entry = self.server.get_file_entry(prev_snap, rel)
                        if (prev_entry
                                and prev_entry["mtime"] == st.st_mtime
                                and prev_entry["size"] == st.st_size):
                            chunk_hashes = prev_entry["chunk_hashes"]
                            self.server.copy_refs(prev_snap, snap_name, chunk_hashes)
                            # Link data entry if metadata unchanged, else write new
                            prev_meta = self.server.get_entry_metadata(prev_snap, rel)
                            cur_acl = _get_acl_text(fpath)
                            if (prev_meta
                                    and prev_meta["uid"] == st.st_uid
                                    and prev_meta["gid"] == st.st_gid
                                    and stat.S_IMODE(prev_meta["mode"]) == stat.S_IMODE(mode)
                                    and prev_meta["acl"] == cur_acl):
                                self.server.link_entry(prev_snap, snap_name, rel)
                            else:
                                meta = {
                                    "type": "file",
                                    "mode": mode,
                                    "uid": st.st_uid, "gid": st.st_gid,
                                    "atime": st.st_atime, "mtime": st.st_mtime,
                                    "acl": cur_acl,
                                    "size": st.st_size,
                                    "chunk_hashes": chunk_hashes,
                                }
                                self.server.write_entry(snap_name, rel, meta)
                                entries.append((rel, meta))
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
                                self.server.add_ref(snap_name, h)

                        meta = {
                            "type": "file",
                            "mode": mode,
                            "uid": st.st_uid, "gid": st.st_gid,
                            "atime": st.st_atime, "mtime": st.st_mtime,
                            "acl": _get_acl_text(fpath),
                            "size": st.st_size,
                            "chunk_hashes": chunk_hashes,
                        }
                        self.server.write_entry(snap_name, rel, meta)
                        entries.append((rel, meta))

                elif entry_type == "symlink":
                    prev_meta = self.server.get_entry_metadata(prev_snap, rel) if prev_snap else None
                    if (prev_meta
                            and prev_meta["uid"] == st.st_uid
                            and prev_meta["gid"] == st.st_gid
                            and self.server.link_entry(prev_snap, snap_name, rel)):
                        pass
                    else:
                        meta = {
                            "type": "symlink",
                            "mode": mode,
                            "uid": st.st_uid, "gid": st.st_gid,
                            "atime": st.st_atime, "mtime": st.st_mtime,
                            "symlink_target": os.readlink(fpath),
                        }
                        self.server.write_entry(snap_name, rel, meta)
                        entries.append((rel, meta))

                elif entry_type == "hardlink":
                    prev_meta = self.server.get_entry_metadata(prev_snap, rel) if prev_snap else None
                    if (prev_meta
                            and prev_meta["uid"] == st.st_uid
                            and prev_meta["gid"] == st.st_gid
                            and self.server.link_entry(prev_snap, snap_name, rel)):
                        pass
                    else:
                        meta = {
                            "type": "hardlink",
                            "link_target": seen_inodes[ino_key],
                            "mode": mode,
                            "uid": st.st_uid, "gid": st.st_gid,
                            "atime": st.st_atime, "mtime": st.st_mtime,
                        }
                        self.server.write_entry(snap_name, rel, meta)
                        entries.append((rel, meta))
                    continue

                elif entry_type in ("blockdev", "chardev"):
                    prev_meta = self.server.get_entry_metadata(prev_snap, rel) if prev_snap else None
                    if (prev_meta
                            and prev_meta["uid"] == st.st_uid
                            and prev_meta["gid"] == st.st_gid
                            and stat.S_IMODE(prev_meta["mode"]) == stat.S_IMODE(mode)
                            and self.server.link_entry(prev_snap, snap_name, rel)):
                        pass
                    else:
                        meta = {
                            "type": entry_type,
                            "mode": mode,
                            "uid": st.st_uid, "gid": st.st_gid,
                            "atime": st.st_atime, "mtime": st.st_mtime,
                            "devmajor": os.major(st.st_rdev),
                            "devminor": os.minor(st.st_rdev),
                        }
                        self.server.write_entry(snap_name, rel, meta)
                        entries.append((rel, meta))

                elif entry_type in ("fifo", "socket"):
                    prev_meta = self.server.get_entry_metadata(prev_snap, rel) if prev_snap else None
                    if (prev_meta
                            and prev_meta["uid"] == st.st_uid
                            and prev_meta["gid"] == st.st_gid
                            and stat.S_IMODE(prev_meta["mode"]) == stat.S_IMODE(mode)
                            and self.server.link_entry(prev_snap, snap_name, rel)):
                        pass
                    else:
                        meta = {
                            "type": entry_type,
                            "mode": mode,
                            "uid": st.st_uid, "gid": st.st_gid,
                            "atime": st.st_atime, "mtime": st.st_mtime,
                        }
                        self.server.write_entry(snap_name, rel, meta)
                        entries.append((rel, meta))

            except (PermissionError, OSError) as exc:
                logger.warning("Skipping %s: %s", fpath, exc)

        if dry_run:
            return snap_name

        # Pass 2: metadata via server — deepest paths first
        for rel, meta in sorted(entries, key=lambda e: e[0], reverse=True):
            self.server.set_entry_metadata(snap_name, rel, meta)

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
        self.server.finalize_snapshot(snap_name)
        logger.info("Snapshot: %s", self.server.snap_dir(snap_name))
        return snap_name

    def restore(self, snap_name: str, dest: str,
                filter_path: Optional[str] = None,
                dry_run: bool = False) -> None:
        """Restore a snapshot (or a single file/dir) to dest."""
        if filter_path is not None:
            logger.info("Restoring '%s:%s' → %s", snap_name, filter_path, dest)
        else:
            logger.info("Restoring '%s' → %s", snap_name, dest)

        dest = os.path.abspath(dest)
        entry_list = self.server.list_entries(snap_name, filter_path)

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
        """Format a list of snapshot entries into human-readable strings."""
        _type_char = {
            "file": "-", "dir": "d", "symlink": "l", "hardlink": "h",
            "blockdev": "b", "chardev": "c", "fifo": "p", "socket": "s",
        }
        lines = []
        for e in entries:
            tc = _type_char.get(e["type"], "?")
            size = e.get("size", 0)
            rel = e["rel_path"]
            suffix = ""
            if e["type"] == "symlink":
                suffix = f" -> {e['symlink_target']}"
            elif e["type"] == "hardlink":
                suffix = f" => {e['link_target']}"
            lines.append(
                f"{tc} {e['uid']:>5}:{e['gid']:<5} {size:>10}  {rel}{suffix}"
            )
        return lines


# ---------------------------------------------------------------------------
# Verify (uses both server and client)
# ---------------------------------------------------------------------------

def cmd_verify(server: BackupServer, client: BackupClient, snap_name: str) -> bool:
    data_dir = server.snap_data_dir(snap_name)
    refs_dir = server.snap_refs_dir(snap_name)
    if not data_dir.exists():
        raise FileNotFoundError(f"Snapshot not found: {snap_name}")

    errors = 0
    checked = 0

    for dirpath, _, filenames in os.walk(str(data_dir)):
        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            st = os.lstat(fpath)
            if not stat.S_ISREG(st.st_mode):
                continue

            with open(fpath, "r") as fh:
                lines = fh.read().strip().split("\n")

            if not lines:
                continue

            # Skip non-file marker entries (hardlinks, devices, fifos, sockets)
            if lines[0] in ("HARDLINK", "BLOCKDEV", "CHARDEV", "FIFO", "SOCKET"):
                continue

            chunk_hashes = [h for h in lines[1:] if h] if len(lines) > 1 else []

            for h in chunk_hashes:
                if not h:
                    continue
                checked += 1

                # Check ref hardlink exists
                if not (refs_dir / h).exists():
                    logger.error("Missing ref %s  (%s)", h[:16], fpath)
                    errors += 1
                    continue

                # Check block exists
                if not server.block_exists(h):
                    logger.error("Missing block %s  (%s)", h[:16], fpath)
                    errors += 1
                    continue

                # Decrypt and verify hash
                try:
                    encrypted_blob = server.retrieve_block(h)
                    data = client.decrypt_block(encrypted_blob)
                except Exception as exc:
                    logger.error("Decrypt error %s  (%s): %s", h[:16], fpath, exc)
                    errors += 1
                    continue

                if hashlib.sha256(data).hexdigest() != h:
                    logger.error("Hash mismatch %s  (%s)", h[:16], fpath)
                    errors += 1

    if errors == 0:
        print(f"OK  {snap_name}: {checked} blocks verified")
        return True
    print(f"FAILED  {snap_name}: {errors}/{checked} blocks with errors")
    return False
