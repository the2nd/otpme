# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import stuff
from otpme.lib import config
from otpme.lib.cache import pass_hash_cache
from otpme.lib.encryption import hash_password

from otpme.lib.exceptions import *

def gen_one_iter_hash(username, password, hash_type="PBKDF2", quiet=True):
    """ Generate OTPme one iteration password hash. """
    if not config.password_hash_salt:
        msg = "Missing password hash salt."
        raise OTPmeException(msg)
    salt = "%s%s" % (config.password_hash_salt, username)
    result = hash_password(password,
                        salt=salt,
                        hash_type=hash_type,
                        iterations=1,
                        quiet=quiet)
    pass_hash = result['hash']
    return pass_hash

# FIXME: make password caching optional! Add config file option for it?
@pass_hash_cache.cache_function()
def gen_pass_hash(username, password, hash_type=None, hash_args=None, quiet=False):
    """ Generate OTPme password hash. """
    # FIXME: is this still the case? We need a better description here!!!
    # NOTE: Using a fixed salt is needed for our session cache to work, because
    #       we need a uniq hash as dict key. We add the username to the salt to
    #       make it a little bit more uniq.
    if hash_type is None:
        hash_type = "PBKDF2"
    if not hash_args:
        # Get default hash args.
        default_args = config.get_hash_type_default_otps(hash_type)
        default_args['hash_type'] = hash_type
        hash_args = [default_args]
    else:
        # Make sure we got valid hash args.
        test_args = stuff.copy_object(hash_args)
        for x_args in test_args:
            try:
                x_args.pop('salt')
            except KeyError:
                pass
            x_hash_type = x_args.pop('hash_type')
            x_default_args = config.get_hash_type_default_otps(x_hash_type)
            for x in x_args:
                x_val = x_args[x]
                if x in x_default_args:
                    x_default_val = x_default_args[x]
                    x_default_val_type = type(x_default_val)
                    x_val_type = type(x_val)
                    if not isinstance(x_val, x_default_val_type):
                        msg = ("Invalid value. Required %s but got %s: %s=%s"
                                % (x_default_val_type, x_val_type, x, x_val))
                        raise OTPmeException(msg)
                    continue
                msg = ("Invalid hash argument: %s: %s=%s"
                        % (x_hash_type, x, x_val))
                raise OTPmeException(msg)
    # Make sure we do not modify hash args dict.
    hash_args = stuff.copy_object(hash_args)
    # Generate password hash.
    result = {}
    _hash_args = []
    p = password
    pass_hash = None
    for x_args in hash_args:
        try:
            salt = x_args.pop("salt")
        except KeyError:
            salt = "%s:%s" % (config.password_hash_salt, username)
        x_hash_data = hash_password(p,
                                salt=salt,
                                quiet=quiet,
                                **x_args)
        p = x_hash_data.pop('hash')
        pass_hash = p
        _hash_args.append(x_hash_data)
    result['hash'] = pass_hash
    result['hash_args'] = _hash_args
    return result
