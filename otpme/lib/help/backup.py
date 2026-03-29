# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except:
    pass

from . import register_cmd_help

def register():
    register_cmd_help(command="backup", help_dict=cmd_help)

cmd_help = {
    '_need_command'             : True,
    '_include_global_opts'      : True,
    '_usage_help'               : _("Usage: otpme-backup {command}"),

    'start'    : {
                    '_cmd_usage_help' : _('Usage: otpme-backup start [--dry-run] [--skip-special] [--exclude <path>] [--include <path>] [--apply-retention] {backup_object}'),
                    'cmd'   :   '--exclude :+exclude+: --include :+include+: --skip-special :skip_special=True: --apply-retention :apply_retention=True: --dry-run :dry_run=True: <backup_object>',
                    '_help' :   {
                                    'cmd'                           : _('Start backup for object <backup_object>.'),
                                    '--dry-run'                     : _('Just print what would be backed-up.'),
                                    '--exclude <path>'              : _('Exclude <path> from backup.'),
                                    '--include <path>'              : _('Include <path> in backup.'),
                                    '--skip-special'                : _('Skip special files (device files etc.).'),
                                    '--apply-retention'             : _('Instruct server to apply backup retention.'),
                                },
                },

    'restore'    : {
                    '_cmd_usage_help' : _('Usage: otpme-backup restore [--dry-run] --snapshot <snapshot> [--path <path>] --destination <destination_dir> {backup_object}'),
                    'cmd'   :   '--path :path: --destination :destination_dir: --snapshot :snap_name: --dry-run :dry_run=True: <backup_object>',
                    '_help' :   {
                                    'cmd'                               : _('Restore from backup repository.'),
                                    '--dry-run'                         : _('Just print what would be restored.'),
                                    '--snapshot <snapshot>'             : _('Restore from snapshot.'),
                                    '--path <path>'                     : _('Restore path <path>.'),
                                    '--destination <destination_dir>'   : _('Restore to <destination_dir>.'),
                                },
                },

    'list'    : {
                    '_cmd_usage_help' : _('Usage: otpme-backup list {backup_object}'),
                    'cmd'   :   '<backup_object>',
                    '_help' :   {
                                    'cmd'                           : _('List backup snapshots.'),
                                },
                },

    'ls'    : {
                    '_cmd_usage_help' : _('Usage: otpme-backup ls [--full-path] [--recursive] {backup_object} {snapshot} [path}'),
                    'cmd'   :   '--full-path :full_path=True: --recursive :recursive=True: <backup_object> <snap_name> [path]',
                    '_help' :   {
                                    'cmd'                           : _('List backup snapshots.'),
                                    '--full-path'                   : _('Output full path.'),
                                    '--recursive'                   : _('List recursive.'),
                                },
                },

    }
