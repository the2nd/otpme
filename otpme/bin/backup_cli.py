#!/usr/bin/env python3
# NOTE: This script was written by claude code!
"""
OTPMe Backup CLI — thin wrapper around otpme.lib.classes.backup.

All backup logic lives in the module; this script only provides
the command-line interface and standalone bootstrapping.
"""

import os
import sys
import types
import hashlib
import logging
import getpass
import argparse
from pathlib import Path

# ---------------------------------------------------------------------------
# Bootstrap: when running standalone (not inside the full OTPme framework),
# provide the minimal shims that otpme.lib.classes.backup expects.
# ---------------------------------------------------------------------------

_script_dir = os.path.dirname(os.path.abspath(os.path.realpath(__file__)))
_package_dir = os.path.dirname(_script_dir)
_package_dir = os.path.dirname(_package_dir)
if _package_dir not in sys.path:
    sys.path.insert(0, _package_dir)

log = logging.getLogger("otpme-backup")

def _ensure_shims():
    """Create minimal otpme.lib.config and otpme.lib.exceptions modules
    if they are not importable (i.e. when running outside the OTPme tree)."""
    try:
        from otpme.lib.classes.backup import BackupServer as _test
        # Full framework available — just ensure logger is set
        from otpme.lib import config as _cfg
        if not hasattr(_cfg, 'logger') or _cfg.logger is None:
            _cfg.logger = log
        return
    except (ImportError, AttributeError):
        pass

    # Build shim packages: otpme → otpme.lib → otpme.lib.classes
    for mod_name in ("otpme", "otpme.lib", "otpme.lib.classes"):
        if mod_name not in sys.modules:
            pkg = types.ModuleType(mod_name)
            pkg.__path__ = [os.path.join(_script_dir, *mod_name.split(".")[1:])]
            pkg.__package__ = mod_name
            sys.modules[mod_name] = pkg

    # config shim — only needs .logger
    config_shim = types.ModuleType("otpme.lib.config")
    config_shim.logger = log
    sys.modules["otpme.lib.config"] = config_shim
    sys.modules["otpme.lib"].config = config_shim

    # exceptions shim
    exc_shim = types.ModuleType("otpme.lib.exceptions")
    sys.modules["otpme.lib.exceptions"] = exc_shim
    sys.modules["otpme.lib"].exceptions = exc_shim

_ensure_shims()

# Add PYTHONPATH.
PYTHONPATH_FILE = "/etc/otpme/PYTHONPATH"
if os.path.exists(PYTHONPATH_FILE):
    fd = open(PYTHONPATH_FILE, "r")
    try:
        for x in fd.readlines():
            x = x.replace("\n", "")
            if x in sys.path:
                continue
            sys.path.insert(0, x)
    finally:
        fd.close()

from otpme.lib.classes.backup import BackupServer, BackupClient, cmd_verify


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="OTPMe deduplicated encrypted backup",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-d", "--backup-dir", required=True,
                        help="Backup storage directory")
    parser.add_argument("-p", "--password-file",
                        help="File with encryption password")
    parser.add_argument("-k", "--key",
                        help="AES-256 key as hex string (64 hex chars, alternative to password)")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--no-compress", action="store_true",
                        help="Disable zlib compression (encrypt only)")

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    p = sub.add_parser("backup", help="Create a new backup")
    p.add_argument("source", help="Source directory")
    p.add_argument("--name", help="Snapshot name (default: ISO timestamp)")
    p.add_argument("--special-files", action="store_true",
                    help="Include device nodes, FIFOs, and sockets")
    p.add_argument("--exclude", action="append", default=[],
                    metavar="PATTERN",
                    help="Exclude paths matching fnmatch pattern (repeatable)")
    p.add_argument("--include", action="append", default=[],
                    metavar="PATTERN",
                    help="Include paths matching fnmatch pattern, overrides --exclude (repeatable)")
    p.add_argument("--dry-run", action="store_true",
                    help="Show what would be backed up without storing anything")
    p.add_argument("--mode", choices=["tree", "pack"], default=None,
                    help="Repository mode: 'tree' (default, FUSE-mountable) or 'pack' (index-only, no tree/meta files)")

    p = sub.add_parser("restore", help="Restore a backup (or a single file/dir)")
    p.add_argument("snapshot", help="Snapshot name")
    p.add_argument("dest",     help="Destination path (directory for full restore, file path for --path)")
    p.add_argument("--path",   help="Restore only this path from the snapshot (relative to backup root)")
    p.add_argument("--dry-run", action="store_true",
                    help="Show what would be restored without writing anything")

    p = sub.add_parser("delete", help="Delete a snapshot and GC orphaned blocks")
    p.add_argument("snapshot", help="Snapshot name")

    sub.add_parser("list", help="List available snapshots")

    p = sub.add_parser("ls", help="List contents of a snapshot")
    p.add_argument("snapshot", help="Snapshot name")
    p.add_argument("path", nargs="?", default=None,
                    help="List only this sub-path (relative to backup root)")
    p.add_argument("--full-path", action="store_true",
                    help="Show full paths instead of relative to --path")
    p.add_argument("-R", "--recursive", action="store_true",
                    help="List contents recursively (default: direct children only)")

    p = sub.add_parser("verify", help="Verify snapshot integrity")
    p.add_argument("snapshot", help="Snapshot name")

    sub.add_parser("gc", help="Garbage-collect orphaned blocks")

    sub.add_parser("compact", help="Compact databases to reclaim disk space")

    sub.add_parser("repair", help="Repair snap-index (fix duplicate entries)")

    sub.add_parser("repack", help="Compact partially-dead pack files to reclaim space")

    sub.add_parser("rebuild-index", help="Rebuild pack index from pack files")

    p = sub.add_parser("retention", help="Apply retention policy and delete old snapshots")
    p.add_argument("--daily", type=int, default=None,
                    help="Number of daily snapshots to keep (overrides .daily file)")
    p.add_argument("--weekly", type=int, default=None,
                    help="Number of weekly snapshots to keep (overrides .weekly file)")
    p.add_argument("--monthly", type=int, default=None,
                    help="Number of monthly snapshots to keep (overrides .monthly file)")
    p.add_argument("--dry-run", action="store_true",
                    help="Show what would be deleted without actually deleting")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    # Create server (storage-only, no password needed)
    server = BackupServer(args.backup_dir)

    # Commands that need crypto (client)
    needs_client = args.command in ("backup", "restore", "verify", "ls")

    client = None
    if needs_client:
        mode = getattr(args, 'mode', None)
        server.init_repository(mode=mode)
        if args.key:
            raw_key = bytes.fromhex(args.key)
            client = BackupClient(server, key=raw_key, compress=not args.no_compress)
        else:
            pw_file = args.password_file
            password = Path(pw_file).read_text().strip() if pw_file else getpass.getpass("Backup password: ")
            client = BackupClient(server, password=password, compress=not args.no_compress)

    if args.command == "backup":
        client.backup(args.source, args.name,
                       special_files=getattr(args, 'special_files', False),
                       excludes=args.exclude or None,
                       includes=args.include or None,
                       dry_run=getattr(args, 'dry_run', False))
    elif args.command == "restore":
        client.restore(args.snapshot, args.dest, args.path,
                       dry_run=getattr(args, 'dry_run', False))
    elif args.command == "delete":
        server.delete_snapshot(args.snapshot)
    elif args.command == "list":
        snaps = server.list_snapshots()
        if not snaps:
            print("No backups found.")
        else:
            from otpme.lib.classes.backup import _format_size
            print(f"{'NAME':<30}  {'FILES':>7}  {'INODES':>7}  {'DATA':>10}  {'STORED':>10}  {'START':<20}  {'END':<20}  {'DURATION':<14}  STATUS")
            print("-" * 160)
            for s in snaps:
                if s["running"]:
                    since = s["running_since"] or "?"
                    status = f"RUNNING since {since}"
                elif s["complete"]:
                    status = "ok"
                else:
                    status = "INCOMPLETE"
                start = s.get("start_time", "") or ""
                end = s.get("end_time", "") or ""
                dur = s.get("duration", "") or ""
                data = _format_size(s.get("total_bytes", 0))
                stored = _format_size(s.get("stored_bytes", 0))
                print(f"{s['name']:<30}  {s['files']:>7}  {s['inodes']:>7}  {data:>10}  {stored:>10}  {start:<20}  {end:<20}  {dur:<14}  {status}")
            total_files = sum(s['files'] for s in snaps)
            total_inodes = sum(s['inodes'] for s in snaps)
            sum_data = sum(s.get('total_bytes', 0) for s in snaps)
            sum_stored = sum(s.get('stored_bytes', 0) for s in snaps)
            print("-" * 160)
            print(f"{'TOTAL':<30}  {total_files:>7}  {total_inodes:>7}  {_format_size(sum_data):>10}  {_format_size(sum_stored):>10}")
            print(f"\n{len(snaps)} snapshot(s)")
    elif args.command == "ls":
        client.print_contents(args.snapshot, args.path,
                              full_path=getattr(args, 'full_path', False),
                              recursive=getattr(args, 'recursive', False))
    elif args.command == "verify":
        sys.exit(0 if cmd_verify(server, client, args.snapshot) else 1)
    elif args.command == "gc":
        removed = server.gc_orphaned_blocks()
        print(f"Removed {removed} orphaned blocks")
    elif args.command == "compact":
        from otpme.lib.classes.backup import _format_size
        result = server.compact()
        for db_name, saved in result.items():
            print(f"{db_name}: reclaimed {_format_size(saved)}")
        if not result:
            print("Nothing to compact.")
    elif args.command == "repair":
        result = server.repair()
        print(f"Removed {result['orphans']} orphaned entries")
    elif args.command == "repack":
        from otpme.lib.classes.backup import _format_size
        saved = server.repack()
        print(f"Reclaimed {_format_size(saved)}")
    elif args.command == "rebuild-index":
        count = server.rebuild_pack_index()
        print(f"Rebuilt index with {count} entries")
    elif args.command == "retention":
        deleted = server.apply_retention(
            daily=args.daily, weekly=args.weekly, monthly=args.monthly,
            dry_run=getattr(args, 'dry_run', False))
        if deleted:
            verb = "Would delete" if args.dry_run else "Deleted"
            print(f"{verb} {len(deleted)} snapshot(s): {', '.join(deleted)}")
        else:
            print("No snapshots to delete.")


if __name__ == "__main__":
    main()
