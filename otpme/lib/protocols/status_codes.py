# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except Exception:
    pass

OK = 200
ERR = 400
# "Still working on your last request." Sent by a command that takes
# long enough for the other side to wonder, so the read timeout of a
# client does not have to outlast the slowest repository on the worst
# day. The client reads the next frame instead of taking this for the
# answer, see OTPmeClient1._send().
KEEPALIVE = 100
ABORT = 230
NOT_FOUND = 404
SYNC_DISABLED= 433
SERVER_QUIT = 000
CLIENT_QUIT = 111
HOST_DISABLED = 423
NEED_USER_AUTH = 401
NEED_HOST_AUTH = 402
NO_CLUSTER_QUORUM = 403
PERMISSION_DENIED = 405
CLUSTER_NOT_READY = 406
UNKNOWN_OBJECT = 407
NO_CLUSTER_SERVICE = 408
UNKNOWN_LOGIN_SESSION = 409
CONNECTION_REDIRECT = 303
BACKUP_CONNECTION_BROKEN = 410
MASTER_FAILOVER = 411
# The peer will not take this object because it is the master node. Its own
# code, because it is not a failure of the connection and a reconnect
# changes nothing about it: a tree object goes from the master outwards,
# never towards it.
MASTER_NODE_WRITE = 412
# Somebody else holds the backup repository right now (another backup, a
# restore, a repack). Its own code because nothing is wrong and the same
# attempt works later, which is what a backup started by backupd then
# does -- see BackupDaemon.start_backup().
BACKUP_REPO_LOCKED = 413
# The site is in maintenance and hands out no objects: its objects are
# being brought up to new versions, and what a peer fetched now it would
# fetch again when the upgrade is through. Nothing is wrong, the same
# sync works after the maintenance.
SITE_MAINTENANCE = 414
# otpme-agent could not reach the daemon it should send the command to.
# Its own code, so the client behind the agent learns the same as one that
# connects directly: no node is there (ConnectionError), not that the
# command failed. otpme-pass then reads what the host keeps offline.
DAEMON_UNREACHABLE = 415
