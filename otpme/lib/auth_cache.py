# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import time

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except:
    pass

from otpme.lib import stuff

from otpme.lib.exceptions import *

auth_cache = {}

def add(client, username, password, token_uuid=None):
    global auth_cache
    pass_hash = stuff.gen_sha512(password)
    auth_cache[username] = {}
    auth_cache[username]['client'] = client
    auth_cache[username]['pass_hash'] = pass_hash
    auth_cache[username]['cache_time'] = time.time()
    auth_cache[username]['token_uuid'] = token_uuid

def verify(client, username, password, cache_timeout):
    global auth_cache
    try:
        cache_time = auth_cache[username]['cache_time']
    except KeyError:
        raise AuthFailed()
    if (time.time() - cache_time) >= cache_timeout:
        raise AuthFailed()
    try:
        cached_client = auth_cache[username]['client']
    except KeyError:
        raise AuthFailed()
    if cached_client != client:
        raise AuthFailed()
    try:
        cached_pass_hash = auth_cache[username]['pass_hash']
    except KeyError:
        raise AuthFailed()
    pass_hash = stuff.gen_sha512(password)
    if pass_hash != cached_pass_hash:
        raise AuthFailed()
    try:
        auth_token_uuid = auth_cache[username]['token_uuid']
    except KeyError:
        raise AuthFailed()
    return auth_token_uuid
