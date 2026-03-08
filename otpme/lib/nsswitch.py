# -*- coding: utf-8 -*-
# This module was written by claude code.
import os
import ctypes

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except:
    pass

from otpme.lib.exceptions import *

NSS_STATUS_SUCCESS = 1
NSSWITCH_CONF = "/etc/nsswitch.conf"

class _GroupStruct(ctypes.Structure):
    _fields_ = [
        ('gr_name',   ctypes.c_char_p),
        ('gr_passwd', ctypes.c_char_p),
        ('gr_gid',    ctypes.c_uint),
        ('gr_mem',    ctypes.POINTER(ctypes.c_char_p)),
    ]

class _PasswdStruct(ctypes.Structure):
    _fields_ = [
        ('pw_name',   ctypes.c_char_p),
        ('pw_passwd', ctypes.c_char_p),
        ('pw_uid',    ctypes.c_uint),
        ('pw_gid',    ctypes.c_uint),
        ('pw_gecos',  ctypes.c_char_p),
        ('pw_dir',    ctypes.c_char_p),
        ('pw_shell',  ctypes.c_char_p),
    ]

def get_sources(database):
    """Read NSS sources for the given database from /etc/nsswitch.conf."""
    sources = []
    try:
        with open(NSSWITCH_CONF, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if line.startswith(database + ':'):
                    parts = line.split(':', 1)[1].split()
                    # Filter out action conditions like [NOTFOUND=return].
                    sources = [p for p in parts if not p.startswith('[')]
                    break
    except Exception as e:
        msg = "Could not read %s: %s" % (NSSWITCH_CONF, e)
        raise OTPmeException(msg)
    return sources

def _load_nss_module(source):
    """Load libnss_<source>.so.2 and return the ctypes CDLL object."""
    lib_name = 'libnss_%s.so.2' % source
    try:
        return ctypes.CDLL(lib_name, use_errno=True)
    except OSError as e:
        raise OTPmeException("Could not load NSS module '%s': %s" % (lib_name, e))

def group_exists(group_name, skip_sources=None):
    """Check if a group exists in any NSS source except those in skip_sources.

    Returns the source name where the group was found, or None.
    """
    if skip_sources is None:
        skip_sources = []
    sources = get_sources('group')
    for source in sources:
        if source in skip_sources:
            continue
        try:
            lib = _load_nss_module(source)
            func = getattr(lib, '_nss_%s_getgrnam_r' % source)
        except Exception:
            continue
        func.restype = ctypes.c_int
        func.argtypes = [
            ctypes.c_char_p,
            ctypes.POINTER(_GroupStruct),
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.POINTER(_GroupStruct)),
        ]
        buf = ctypes.create_string_buffer(1024)
        entry = _GroupStruct()
        result = ctypes.POINTER(_GroupStruct)()
        status = func(
            group_name.encode(),
            ctypes.byref(entry),
            buf, 1024,
            ctypes.byref(result),
        )
        if status == NSS_STATUS_SUCCESS:
            return source
    return None

def user_exists(user_name, skip_sources=None):
    """Check if a user exists in any NSS source except those in skip_sources.

    Returns the source name where the user was found, or None.
    """
    if skip_sources is None:
        skip_sources = []
    sources = get_sources('passwd')
    for source in sources:
        if source in skip_sources:
            continue
        try:
            lib = _load_nss_module(source)
            func = getattr(lib, '_nss_%s_getpwnam_r' % source)
        except Exception:
            continue
        func.restype = ctypes.c_int
        func.argtypes = [
            ctypes.c_char_p,
            ctypes.POINTER(_PasswdStruct),
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.POINTER(_PasswdStruct)),
        ]
        buf = ctypes.create_string_buffer(1024)
        entry = _PasswdStruct()
        result = ctypes.POINTER(_PasswdStruct)()
        status = func(
            user_name.encode(),
            ctypes.byref(entry),
            buf, 1024,
            ctypes.byref(result),
        )
        if status == NSS_STATUS_SUCCESS:
            return source
    return None
