# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

OK = "200"
ERR = "400"
ABORT = "230"
NOT_FOUND = "404"
SYNC_DISABLED= "433"
SERVER_QUIT = "000"
CLIENT_QUIT = "111"
HOST_DISABLED = "423"
NEED_USER_AUTH = "401"
NEED_HOST_AUTH = "402"
NO_CLUSTER_QUORUM = "403"
PERMISSION_DENIED = "405"
CLUSTER_NOT_READY = "406"
UNKNOWN_OBJECT = "407"
CONNECTION_REDIRECT = "303"
