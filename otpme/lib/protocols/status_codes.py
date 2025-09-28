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

OK = 200
ERR = 400
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
