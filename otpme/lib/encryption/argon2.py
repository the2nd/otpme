# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import argon2

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import stuff
from otpme.lib import config

from otpme.lib.exceptions import *

ARGON2D_DEFAULTS = {
            'hash_algo'     : 'Argon2_d',
            'iterations'    : 3,
            'min_mem'       : 65536,
            'max_mem'       : 262144,
            'memory'        : 65536,
            'threads'       : 4,
            'key_len'       : 128,
            }
ARGON2I_DEFAULTS = {
            'hash_algo'     : 'Argon2_i',
            'iterations'    : 3,
            'min_mem'       : 65536,
            'max_mem'       : 262144,
            'memory'        : 65536,
            'threads'       : 4,
            'key_len'       : 128,
            }

CONFIG_OPTIONS = {
                'default_pw_hash_argon2i_iterations'      : {
                                                'type'      : int,
                                                'argument'  : 'iterations',
                                                'default'   : ARGON2I_DEFAULTS['iterations'],
                                            },
                'default_pw_hash_argon2i_min_mem'      : {
                                                'type'      : int,
                                                'argument'  : 'min_mem',
                                                'default'   : ARGON2I_DEFAULTS['min_mem'],
                                            },
                'default_pw_hash_argon2i_max_mem'      : {
                                                'type'      : int,
                                                'argument'  : 'max_mem',
                                                'default'   : ARGON2I_DEFAULTS['max_mem'],
                                            },
                'default_pw_hash_argon2i_threads'      : {
                                                'type'      : int,
                                                'argument'  : 'threads',
                                                'default'   : ARGON2I_DEFAULTS['threads'],
                                            },
                'default_pw_hash_argon2i_key_len'      : {
                                                'type'      : int,
                                                'argument'  : 'key_len',
                                                'default'   : ARGON2I_DEFAULTS['key_len'],
                                            },
                'default_pw_hash_argon2d_iter'      : {
                                                'type'      : int,
                                                'argument'  : 'iterations',
                                                'default'   : ARGON2D_DEFAULTS['iterations'],
                                            },
                'default_pw_hash_argon2d_min_mem'      : {
                                                'type'      : int,
                                                'argument'  : 'min_mem',
                                                'default'   : ARGON2D_DEFAULTS['min_mem'],
                                            },
                'default_pw_hash_argon2d_max_mem'      : {
                                                'type'      : int,
                                                'argument'  : 'max_mem',
                                                'default'   : ARGON2D_DEFAULTS['max_mem'],
                                            },
                'default_pw_hash_argon2d_threads'      : {
                                                'type'      : int,
                                                'argument'  : 'threads',
                                                'default'   : ARGON2D_DEFAULTS['threads'],
                                            },
                'default_pw_hash_argon2d_key_len'      : {
                                                'type'      : int,
                                                'argument'  : 'key_len',
                                                'default'   : ARGON2D_DEFAULTS['key_len'],
                                            },
                }

logger = config.logger

REGISTER_BEFORE = []
REGISTER_AFTER = ["otpme.lib.encoding.base"]

def register():
    config.register_hash_type(hash_type="Argon2_d",
                            hash_func=derive,
                            default_opts=ARGON2D_DEFAULTS,
                            config_opts=CONFIG_OPTIONS)
    config.register_hash_type(hash_type="Argon2_i",
                            hash_func=derive,
                            default_opts=ARGON2I_DEFAULTS,
                            config_opts=CONFIG_OPTIONS)
    # Object types our config parameters are valid for.
    object_types = [
                    'realm',
                    'site',
                    'unit',
                    'user',
                    'token',
                    ]
    for config_name in CONFIG_OPTIONS:
        ctype = CONFIG_OPTIONS[config_name]['type']
        default_value = CONFIG_OPTIONS[config_name]['default']
        config.register_config_parameter(name=config_name,
                                        ctype=ctype,
                                        default_value=default_value,
                                        object_types=object_types)

def derive(secret, salt=None, key_len=128, hash_algo="Argon2_i",
    min_mem=None, max_mem=None, memory=None, threads=None,
    iterations=None, quiet=True):
    #iterations=None, quiet=True, **kwargs):
    """ Generate secret hash. """

    # Encode pw and salt.
    _secret = secret.encode("utf-8")
    _salt = salt
    if salt is not None:
        _salt = salt.encode("utf-8")
    if iterations is not None:
        iterations = int(iterations)

    # Get default opts for given hash type.
    default_opts = config.get_hash_type_default_otps(hash_algo)

    # Calculate Argon2 memory parameter.
    if key_len is None:
        key_len = default_opts['key_len']
    if memory is None:
        memory = default_opts['memory']
    elif memory == "auto":
        if min_mem is None:
            min_mem = default_opts['min_mem']
        if max_mem is None:
            max_mem = default_opts['max_mem']
        mem_free_kb = stuff.get_free_memory() / 1024
        if mem_free_kb <= min_mem:
            memory = min_mem
        elif mem_free_kb >= max_mem:
            memory = max_mem
        else:
            memory = mem_free_kb / 100 * 70
        memory = int(memory)
    if not threads:
        threads = default_opts['threads']
    if not quiet:
        logger.debug("Threads:    %s" % threads)
        logger.debug("Memory:     %sM" % (memory / 1024))
        logger.debug("Iterations: %s" % iterations)
    try:
        argon_type = getattr(argon2.Argon2Type, hash_algo)
    except Exception:
        raise OTPmeException(_("Unknown argon_type: %s") % hash_algo)
    try:
        _hash = argon2.argon2_hash(_secret, _salt,
                                t=iterations,
                                m=memory,
                                p=threads,
                                buflen=key_len,
                                argon_type=argon_type)
    except Exception as e:
        config.raise_exception()
        msg = (_("Error generating argon2 hash: %s") % e)
        raise OTPmeException(msg)

    # Build result.
    result = {
            'hash_type'     : hash_algo,
            'iterations'    : iterations,
            'hash_algo'     : hash_algo,
            'key_len'       : key_len,
            'threads'       : threads,
            'memory'        : memory,
            'salt'          : salt,
            'hash'          : _hash,
            }

    return result
