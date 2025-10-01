# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except:
    pass

from otpme.lib import stuff
from otpme.lib import config
from otpme.lib import filetools

from otpme.lib.exceptions import *

# Get logger.
logger = config.logger

def add_cache(object_id, signer_key):
    """ Add signer public key to cache. """
    from otpme.lib import backend
    # Get user UUID.
    user_uuid = stuff.resolve_oid(object_id)
    # Handle transactions.
    _transaction = backend.get_transaction()
    if _transaction:
        _transaction.add_sign_cache(object_id, user_uuid, signer_key)
        return
    user_oid = stuff.resolve_uuid(user_uuid, object_type="user")
    cache_file = os.path.join(config.sign_key_cache_dir, user_uuid)
    log_msg = _("Adding signer key to cache: {user_oid}: {file}", log=True)[1]
    log_msg = log_msg.format(user_oid=user_oid, file=cache_file)
    logger.debug(log_msg)
    filetools.create_file(path=cache_file,
                        content=signer_key,
                        user=config.user,
                        group=config.group,
                        mode=0o664)

def get_cache(object_id=None, user_uuid=None, verbose=False):
    """ Get signer public key from cache. """
    from otpme.lib import backend
    if not object_id and not user_uuid:
        msg = (_("Need <object_id> or <user_uuid>."))
        raise OTPmeException(msg)
    if not user_uuid:
        user_uuid = stuff.resolve_oid(object_id)
    if not object_id:
        object_id = stuff.resolve_uuid(user_uuid, object_type="user")
    # Handle transactions.
    _transaction = backend.get_transaction()
    if _transaction:
        public_key = _transaction.get_sign_cache(object_id, user_uuid)
        return public_key
    cache_file = os.path.join(config.sign_key_cache_dir, user_uuid)
    if not os.path.exists(cache_file):
        return
    # Read users public key from cache file.
    if verbose:
        log_msg = _("Reading signer key from cache: {object_id}: {file}", log=True)[1]
        log_msg = log_msg.format(object_id=object_id, file=cache_file)
        logger.debug(log_msg)
    try:
        fd = open(cache_file, "r")
        public_key = fd.read().replace("\n", "")
        fd.close()
    except Exception as e:
        msg = _("Error reading singer key from cache: {name}: {file}: {error}")
        msg = msg.format(name=object_id.name, file=cache_file, error=e)
        raise OTPmeException(msg)
    return public_key

def del_cache(object_id):
    """ Del signer public key from cache. """
    from otpme.lib import backend
    # Get user UUID.
    user_uuid = stuff.resolve_oid(object_id)
    # Handle transactions.
    _transaction = backend.get_transaction()
    if _transaction:
        _transaction.del_sign_cache(object_id, user_uuid)
        return
    cache_file = os.path.join(config.sign_key_cache_dir, user_uuid)
    log_msg = _("Removing signer key cache: {object_id}: {file}", log=True)[1]
    log_msg = log_msg.format(object_id=object_id, file=cache_file)
    logger.debug(log_msg)
    if not os.path.exists(cache_file):
        return
    filetools.delete(cache_file)
