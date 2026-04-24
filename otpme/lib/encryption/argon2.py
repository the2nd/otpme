# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
from argon2.low_level import hash_secret_raw
from argon2.low_level import Type as _Argon2Type

# Map OTPme hash_algo names to argon2-cffi types.
_ARGON2_TYPE_MAP = {
    "Argon2_i":  _Argon2Type.I,
    "Argon2_d":  _Argon2Type.D,
    "Argon2_id": _Argon2Type.ID,
}

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import stuff
from otpme.lib import config

from otpme.lib.exceptions import *

ARGON2D_DEFAULTS = {
            'hash_algo'     : 'Argon2_d',
            'iterations'    : 2,
            'min_mem'       : 65536,
            'max_mem'       : 262144,
            'memory'        : 65536,
            'threads'       : 1,
            'key_len'       : 128,
            'version'       : 1,
            # Argon2 spec version. 0x10 keeps bit-compat with hashes the
            # legacy single-file 'argon2' lib produced.
            'argon2_version': 0x10,
            }
ARGON2I_DEFAULTS = {
            'hash_algo'     : 'Argon2_i',
            'iterations'    : 2,
            'min_mem'       : 65536,
            'max_mem'       : 262144,
            'memory'        : 65536,
            'threads'       : 1,
            'key_len'       : 128,
            'version'       : 1,
            'argon2_version': 0x10,
            }
ARGON2ID_DEFAULTS = {
            'hash_algo'     : 'Argon2_id',
            'iterations'    : 2,
            'min_mem'       : 65536,
            'max_mem'       : 262144,
            'memory'        : 65536,
            'threads'       : 1,
            'key_len'       : 128,
            'version'       : 1,
            # Argon2id gets the modern spec version (RFC 9106).
            'argon2_version': 0x13,
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
                'default_pw_hash_argon2id_iterations'      : {
                                                'type'      : int,
                                                'argument'  : 'iterations',
                                                'default'   : ARGON2ID_DEFAULTS['iterations'],
                                            },
                'default_pw_hash_argon2id_min_mem'      : {
                                                'type'      : int,
                                                'argument'  : 'min_mem',
                                                'default'   : ARGON2ID_DEFAULTS['min_mem'],
                                            },
                'default_pw_hash_argon2id_max_mem'      : {
                                                'type'      : int,
                                                'argument'  : 'max_mem',
                                                'default'   : ARGON2ID_DEFAULTS['max_mem'],
                                            },
                'default_pw_hash_argon2id_threads'      : {
                                                'type'      : int,
                                                'argument'  : 'threads',
                                                'default'   : ARGON2ID_DEFAULTS['threads'],
                                            },
                'default_pw_hash_argon2id_key_len'      : {
                                                'type'      : int,
                                                'argument'  : 'key_len',
                                                'default'   : ARGON2ID_DEFAULTS['key_len'],
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
    config.register_hash_type(hash_type="Argon2_id",
                            hash_func=derive,
                            default_opts=ARGON2ID_DEFAULTS,
                            config_opts=CONFIG_OPTIONS)
    # Object types our config parameters are valid for.
    object_types = [
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
    iterations=None, quiet=True, **kwargs):
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
        logger.debug(f"Threads:    {threads}")
        logger.debug(f"Memory:     {memory/1024}M")
        logger.debug(f"Iterations: {iterations}")
    try:
        argon_type = _ARGON2_TYPE_MAP[hash_algo]
    except KeyError as err:
        msg = _("Unknown argon_type: {hash_algo}")
        msg = msg.format(hash_algo=hash_algo)
        raise OTPmeException(msg) from err
    # Argon2 spec version (0x10 / 0x13). Caller may override via kwargs
    # when verifying existing hashes so we reproduce the exact bytes.
    argon2_version = kwargs.get('argon2_version')
    if argon2_version is None:
        argon2_version = default_opts.get('argon2_version', 0x10)
    try:
        _hash = hash_secret_raw(_secret, _salt,
                                time_cost=iterations,
                                memory_cost=memory,
                                parallelism=threads,
                                hash_len=key_len,
                                type=argon_type,
                                version=argon2_version)
    except Exception as e:
        config.raise_exception()
        msg = _("Error generating argon2 hash: {error}")
        msg = msg.format(error=e)
        raise OTPmeException(msg) from e

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
            # OTPme hash-params format version (not the Argon2 spec version).
            'version'       : 1,
            # Argon2 internal spec version (0x10 / 0x13) so verify can
            # reproduce the exact same hash.
            'argon2_version': argon2_version,
            }

    return result
