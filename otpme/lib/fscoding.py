# -*- coding: utf-8 -*-
# OTPmeFS Socket Encoding/Decoding System
# This module provides functions to encode/decode OTPmeFS method calls
# for transmission over sockets without using JSON, msgpack, or other serializers

import struct
from typing import Optional, List, Any, Tuple, Union

# Method codes mapping
METHOD_CODES = {
    'read': 0,
    'write': 1,
    'chmod': 2,
    'chown': 3,
    'create': 4,
    'destroy': 5,
    'getattr': 6,
    'statfs': 7,
    'mkdir': 8,
    'open': 9,
    'release': 10,
    'access': 11,
    'readdir': 12,
    'readlink': 13,
    'rename': 14,
    'rmdir': 15,
    'link': 16,
    'symlink': 17,
    'truncate': 18,
    'unlink': 19,
    'utimens': 20,
    'exists': 21,
    'get_mtime': 22,
    'get_ctime': 28,
    'getxattr': 23,
    'setxattr': 24,
    'listxattr': 25,
    'removexattr': 26,
    'mount': 27,
}

# Reverse mapping for decoding
CODE_TO_METHOD = {v: k for k, v in METHOD_CODES.items()}

def _encode_string(s: str) -> bytes:
    """Encode a string with length prefix"""
    if s is None or s == "":
        return struct.pack('!I', 0)
    s_bytes = s.encode('utf-8')
    return struct.pack('!I', len(s_bytes)) + s_bytes

def _decode_string(data: bytes, offset: int) -> Tuple[Optional[str], int]:
    """Decode a string with length prefix"""
    if offset + 4 > len(data):
        raise ValueError("Not enough data to read string length")
    try:
        length = struct.unpack('!I', data[offset:offset+4])[0]
    except struct.error as e:
        raise ValueError(f"Failed to unpack string length: {e}")
    offset += 4
    if length == 0:
        return "", offset
    if offset + length > len(data):
        raise ValueError("Not enough data to read string")
    s = data[offset:offset+length].decode('utf-8')
    return s, offset + length

def _encode_bytes(b: Optional[bytes]) -> bytes:
    """Encode bytes with length prefix"""
    if b is None:
        return struct.pack('!I', 0)
    return struct.pack('!I', len(b)) + b

def _decode_bytes(data: bytes, offset: int) -> Tuple[Optional[bytes], int]:
    """Decode bytes with length prefix"""
    if offset + 4 > len(data):
        raise ValueError("Not enough data to read bytes length")
    try:
        length = struct.unpack('!I', data[offset:offset+4])[0]
    except struct.error as e:
        raise ValueError(f"Failed to unpack bytes length: {e}")
    offset += 4
    if length == 0:
        return None, offset
    if offset + length > len(data):
        raise ValueError("Not enough data to read bytes")
    b = data[offset:offset+length]
    return b, offset + length

def _encode_int(i: Optional[int]) -> bytes:
    """Encode an integer (nullable)"""
    if i is None:
        return b'\x00' + struct.pack('!i', 0)
    return b'\x01' + struct.pack('!i', i)

def _decode_int(data: bytes, offset: int) -> Tuple[Optional[int], int]:
    """Decode an integer (nullable)"""
    if offset + 5 > len(data):
        raise ValueError("Not enough data to read int")
    has_value = data[offset] == 1
    offset += 1
    try:
        i = struct.unpack('!i', data[offset:offset+4])[0]
    except struct.error as e:
        raise ValueError(f"Failed to unpack int: {e}")
    offset += 4
    return i if has_value else None, offset

def _encode_float(f: Optional[float]) -> bytes:
    """Encode a float (nullable)"""
    if f is None:
        return b'\x00' + struct.pack('!d', 0.0)
    return b'\x01' + struct.pack('!d', f)

def _decode_float(data: bytes, offset: int) -> Tuple[Optional[float], int]:
    """Decode a float (nullable)"""
    if offset + 9 > len(data):
        raise ValueError("Not enough data to read float")
    has_value = data[offset] == 1
    offset += 1
    try:
        f = struct.unpack('!d', data[offset:offset+8])[0]
    except struct.error as e:
        raise ValueError(f"Failed to unpack float: {e}")
    offset += 8
    return f if has_value else None, offset

def _encode_tuple_times(times: Optional[Tuple[int, int]]) -> bytes:
    """Encode times tuple (atime, mtime) as nanoseconds integers"""
    if times is None:
        return b'\x00'
    return b'\x01' + struct.pack('!QQ', int(times[0]), int(times[1]))

def _decode_tuple_times(data: bytes, offset: int) -> Tuple[Optional[Tuple[int, int]], int]:
    """Decode times tuple (atime, mtime) as nanoseconds integers"""
    if offset + 1 > len(data):
        raise ValueError("Not enough data to read times flag")
    has_value = data[offset] == 1
    offset += 1
    if not has_value:
        return None, offset
    if offset + 16 > len(data):
        raise ValueError("Not enough data to read times tuple")
    try:
        atime, mtime = struct.unpack('!QQ', data[offset:offset+16])
    except struct.error as e:
        raise ValueError(f"Failed to unpack times tuple: {e}")
    return (int(atime), int(mtime)), offset + 16

def _encode_list_strings(lst: Optional[List[str]]) -> bytes:
    """Encode a list of strings"""
    if lst is None:
        return struct.pack('!I', 0)
    result = struct.pack('!I', len(lst))
    for s in lst:
        result += _encode_string(s)
    return result

def _decode_list_strings(data: bytes, offset: int) -> Tuple[Optional[List[str]], int]:
    """Decode a list of strings"""
    if offset + 4 > len(data):
        raise ValueError("Not enough data to read list length")
    try:
        length = struct.unpack('!I', data[offset:offset+4])[0]
    except struct.error as e:
        raise ValueError(f"Failed to unpack list length: {e}")
    offset += 4
    if length == 0:
        return [], offset
    result = []
    for _ in range(length):
        s, offset = _decode_string(data, offset)
        result.append(s)
    return result, offset

# Encoding functions for each method

def encode_read(path: str, size: int, offset: int) -> bytes:
    """Encode read method call"""
    packet = struct.pack('!B', METHOD_CODES['read'])
    packet += _encode_string(path)
    packet += struct.pack('!II', size, offset)
    return packet

def encode_write(path: str, offset: int) -> bytes:
    """Encode write method call"""
    packet = struct.pack('!B', METHOD_CODES['write'])
    packet += _encode_string(path)
    packet += struct.pack('!I', offset)
    return packet

def encode_chmod(path: str, mode: int) -> bytes:
    """Encode chmod method call"""
    packet = struct.pack('!B', METHOD_CODES['chmod'])
    packet += _encode_string(path)
    packet += struct.pack('!I', mode)
    return packet

def encode_chown(path: str, uid: int, gid: int) -> bytes:
    """Encode chown method call"""
    packet = struct.pack('!B', METHOD_CODES['chown'])
    packet += _encode_string(path)
    # Use signed integers to allow -1 values
    packet += struct.pack('!ii', uid, gid)
    return packet

def encode_create(path: str, mode: int) -> bytes:
    """Encode create method call"""
    packet = struct.pack('!B', METHOD_CODES['create'])
    packet += _encode_string(path)
    packet += struct.pack('!I', mode)
    return packet

def encode_destroy(path: str) -> bytes:
    """Encode destroy method call"""
    packet = struct.pack('!B', METHOD_CODES['destroy'])
    packet += _encode_string(path)
    return packet

def encode_getattr(path: str) -> bytes:
    """Encode getattr method call"""
    packet = struct.pack('!B', METHOD_CODES['getattr'])
    packet += _encode_string(path)
    return packet

def encode_statfs(path: str) -> bytes:
    """Encode statfs method call"""
    packet = struct.pack('!B', METHOD_CODES['statfs'])
    packet += _encode_string(path)
    return packet

def encode_mkdir(path: str, mode: int) -> bytes:
    """Encode mkdir method call"""
    packet = struct.pack('!B', METHOD_CODES['mkdir'])
    packet += _encode_string(path)
    packet += struct.pack('!I', mode)
    return packet

def encode_open(path: str, flags: int) -> bytes:
    """Encode open method call"""
    packet = struct.pack('!B', METHOD_CODES['open'])
    packet += _encode_string(path)
    packet += struct.pack('!I', flags)
    return packet

def encode_release(path: str) -> bytes:
    """Encode release method call"""
    packet = struct.pack('!B', METHOD_CODES['release'])
    packet += _encode_string(path)
    return packet

def encode_access(path: str, amode: int) -> bytes:
    """Encode access method call"""
    packet = struct.pack('!B', METHOD_CODES['access'])
    packet += _encode_string(path)
    packet += struct.pack('!I', amode)
    return packet

def encode_readdir(path: str) -> bytes:
    """Encode readdir method call"""
    packet = struct.pack('!B', METHOD_CODES['readdir'])
    packet += _encode_string(path)
    return packet

def encode_readlink(path: str) -> bytes:
    """Encode readlink method call"""
    packet = struct.pack('!B', METHOD_CODES['readlink'])
    packet += _encode_string(path)
    return packet

def encode_rename(old: str, new: str) -> bytes:
    """Encode rename method call"""
    packet = struct.pack('!B', METHOD_CODES['rename'])
    packet += _encode_string(old)
    packet += _encode_string(new)
    return packet

def encode_rmdir(path: str) -> bytes:
    """Encode rmdir method call"""
    packet = struct.pack('!B', METHOD_CODES['rmdir'])
    packet += _encode_string(path)
    return packet

def encode_link(target: str, source: str) -> bytes:
    """Encode link method call"""
    packet = struct.pack('!B', METHOD_CODES['link'])
    packet += _encode_string(target)
    packet += _encode_string(source)
    return packet

def encode_symlink(target: str, source: str) -> bytes:
    """Encode symlink method call"""
    packet = struct.pack('!B', METHOD_CODES['symlink'])
    packet += _encode_string(target)
    packet += _encode_string(source)
    return packet

def encode_truncate(path: str, length: int) -> bytes:
    """Encode truncate method call"""
    packet = struct.pack('!B', METHOD_CODES['truncate'])
    packet += _encode_string(path)
    packet += struct.pack('!I', length)
    return packet

def encode_unlink(path: str) -> bytes:
    """Encode unlink method call"""
    packet = struct.pack('!B', METHOD_CODES['unlink'])
    packet += _encode_string(path)
    return packet

def encode_utimens(path: str, times: Optional[Tuple[int, int]] = None) -> bytes:
    """Encode utimens method call"""
    packet = struct.pack('!B', METHOD_CODES['utimens'])
    packet += _encode_string(path)
    packet += _encode_tuple_times(times)
    return packet

def encode_exists(path: str) -> bytes:
    """Encode exists method call"""
    packet = struct.pack('!B', METHOD_CODES['exists'])
    packet += _encode_string(path)
    return packet

def encode_get_mtime(path: str) -> bytes:
    """Encode get_mtime method call"""
    packet = struct.pack('!B', METHOD_CODES['get_mtime'])
    packet += _encode_string(path)
    return packet

def encode_get_ctime(path: str) -> bytes:
    """Encode get_ctime method call"""
    packet = struct.pack('!B', METHOD_CODES['get_ctime'])
    packet += _encode_string(path)
    return packet

def encode_getxattr(path: str, name: str, position: int = 0) -> bytes:
    """Encode getxattr method call"""
    packet = struct.pack('!B', METHOD_CODES['getxattr'])
    packet += _encode_string(path)
    packet += _encode_string(name)
    packet += struct.pack('!I', position)
    return packet

def encode_setxattr(path: str, name: str, value: bytes, options: int, position: int = 0) -> bytes:
    """Encode setxattr method call"""
    packet = struct.pack('!B', METHOD_CODES['setxattr'])
    packet += _encode_string(path)
    packet += _encode_string(name)
    packet += _encode_bytes(value)
    packet += struct.pack('!II', options, position)
    return packet

def encode_listxattr(path: str) -> bytes:
    """Encode listxattr method call"""
    packet = struct.pack('!B', METHOD_CODES['listxattr'])
    packet += _encode_string(path)
    return packet

def encode_removexattr(path: str, name: str) -> bytes:
    """Encode removexattr method call"""
    packet = struct.pack('!B', METHOD_CODES['removexattr'])
    packet += _encode_string(path)
    packet += _encode_string(name)
    return packet

def encode_mount(share: str) -> bytes:
    """Encode mount method call"""
    packet = struct.pack('!B', METHOD_CODES['mount'])
    packet += _encode_string(share)
    return packet

# Decoding functions for each method

def decode_read(data: bytes) -> dict:
    """Decode read method call"""
    offset = 1  # Skip method code
    path, offset = _decode_string(data, offset)
    try:
        size, offset_val = struct.unpack('!II', data[offset:offset+8])
    except struct.error as e:
        raise ValueError(f"Failed to unpack read: {e}")
    return {'path': path, 'size': size, 'offset': offset_val}

def decode_write(data: bytes) -> dict:
    """Decode write method call"""
    offset = 1  # Skip method code
    path, offset = _decode_string(data, offset)
    try:
        offset_val = struct.unpack('!I', data[offset:offset+4])[0]
    except struct.error as e:
        raise ValueError(f"Failed to unpack write: {e}")
    return {'path': path, 'offset': offset_val}

def decode_chmod(data: bytes) -> dict:
    """Decode chmod method call"""
    offset = 1  # Skip method code
    path, offset = _decode_string(data, offset)
    try:
        mode = struct.unpack('!I', data[offset:offset+4])[0]
    except struct.error as e:
        raise ValueError(f"Failed to unpack chmod: {e}")
    return {'path': path, 'mode': mode}

def decode_chown(data: bytes) -> dict:
    """Decode chown method call"""
    offset = 1  # Skip method code
    path, offset = _decode_string(data, offset)
    try:
        # Use signed integers to allow -1 values
        uid, gid = struct.unpack('!ii', data[offset:offset+8])
    except struct.error as e:
        raise ValueError(f"Failed to unpack chown: {e}")
    return {'path': path, 'uid': uid, 'gid': gid}

def decode_create(data: bytes) -> dict:
    """Decode create method call"""
    offset = 1  # Skip method code
    path, offset = _decode_string(data, offset)
    try:
        mode = struct.unpack('!I', data[offset:offset+4])[0]
    except struct.error as e:
        raise ValueError(f"Failed to unpack create: {e}")
    return {'path': path, 'mode': mode}

def decode_destroy(data: bytes) -> dict:
    """Decode destroy method call"""
    offset = 1  # Skip method code
    path, offset = _decode_string(data, offset)
    return {'path': path}

def decode_getattr(data: bytes) -> dict:
    """Decode getattr method call"""
    offset = 1  # Skip method code
    path, offset = _decode_string(data, offset)
    return {'path': path}

def decode_statfs(data: bytes) -> dict:
    """Decode statfs method call"""
    offset = 1  # Skip method code
    path, offset = _decode_string(data, offset)
    return {'path': path}

def decode_mkdir(data: bytes) -> dict:
    """Decode mkdir method call"""
    offset = 1  # Skip method code
    path, offset = _decode_string(data, offset)
    try:
        mode = struct.unpack('!I', data[offset:offset+4])[0]
    except struct.error as e:
        raise ValueError(f"Failed to unpack mkdir: {e}")
    return {'path': path, 'mode': mode}

def decode_open(data: bytes) -> dict:
    """Decode open method call"""
    offset = 1  # Skip method code
    path, offset = _decode_string(data, offset)
    try:
        flags = struct.unpack('!I', data[offset:offset+4])[0]
    except struct.error as e:
        raise ValueError(f"Failed to unpack open: {e}")
    return {'path': path, 'flags': flags}

def decode_release(data: bytes) -> dict:
    """Decode release method call"""
    offset = 1  # Skip method code
    path, offset = _decode_string(data, offset)
    return {'path': path}

def decode_access(data: bytes) -> dict:
    """Decode access method call"""
    offset = 1  # Skip method code
    path, offset = _decode_string(data, offset)
    try:
        amode = struct.unpack('!I', data[offset:offset+4])[0]
    except struct.error as e:
        raise ValueError(f"Failed to unpack access: {e}")
    return {'path': path, 'amode': amode}

def decode_readdir(data: bytes) -> dict:
    """Decode readdir method call"""
    offset = 1  # Skip method code
    path, offset = _decode_string(data, offset)
    return {'path': path}

def decode_readlink(data: bytes) -> dict:
    """Decode readlink method call"""
    offset = 1  # Skip method code
    path, offset = _decode_string(data, offset)
    return {'path': path}

def decode_rename(data: bytes) -> dict:
    """Decode rename method call"""
    offset = 1  # Skip method code
    old, offset = _decode_string(data, offset)
    new, offset = _decode_string(data, offset)
    return {'old': old, 'new': new}

def decode_rmdir(data: bytes) -> dict:
    """Decode rmdir method call"""
    offset = 1  # Skip method code
    path, offset = _decode_string(data, offset)
    return {'path': path}

def decode_link(data: bytes) -> dict:
    """Decode link method call"""
    offset = 1  # Skip method code
    target, offset = _decode_string(data, offset)
    source, offset = _decode_string(data, offset)
    return {'target': target, 'source': source}

def decode_symlink(data: bytes) -> dict:
    """Decode symlink method call"""
    offset = 1  # Skip method code
    target, offset = _decode_string(data, offset)
    source, offset = _decode_string(data, offset)
    return {'target': target, 'source': source}

def decode_truncate(data: bytes) -> dict:
    """Decode truncate method call"""
    offset = 1  # Skip method code
    path, offset = _decode_string(data, offset)
    try:
        length = struct.unpack('!I', data[offset:offset+4])[0]
    except struct.error as e:
        raise ValueError(f"Failed to unpack truncate: {e}")
    return {'path': path, 'length': length}

def decode_unlink(data: bytes) -> dict:
    """Decode unlink method call"""
    offset = 1  # Skip method code
    path, offset = _decode_string(data, offset)
    return {'path': path}

def decode_utimens(data: bytes) -> dict:
    """Decode utimens method call"""
    offset = 1  # Skip method code
    path, offset = _decode_string(data, offset)
    times, offset = _decode_tuple_times(data, offset)
    return {'path': path, 'times': times}

def decode_exists(data: bytes) -> dict:
    """Decode exists method call"""
    offset = 1  # Skip method code
    path, offset = _decode_string(data, offset)
    return {'path': path}

def decode_get_mtime(data: bytes) -> dict:
    """Decode get_mtime method call"""
    offset = 1  # Skip method code
    path, offset = _decode_string(data, offset)
    return {'path': path}

def decode_get_ctime(data: bytes) -> dict:
    """Decode get_ctime method call"""
    offset = 1  # Skip method code
    path, offset = _decode_string(data, offset)
    return {'path': path}

def decode_getxattr(data: bytes) -> dict:
    """Decode getxattr method call"""
    offset = 1  # Skip method code
    path, offset = _decode_string(data, offset)
    name, offset = _decode_string(data, offset)
    try:
        position = struct.unpack('!I', data[offset:offset+4])[0]
    except struct.error as e:
        raise ValueError(f"Failed to unpack getxattr: {e}")
    return {'path': path, 'name': name, 'position': position}

def decode_setxattr(data: bytes) -> dict:
    """Decode setxattr method call"""
    offset = 1  # Skip method code
    path, offset = _decode_string(data, offset)
    name, offset = _decode_string(data, offset)
    value, offset = _decode_bytes(data, offset)
    try:
        options, position = struct.unpack('!II', data[offset:offset+8])
    except struct.error as e:
        raise ValueError(f"Failed to unpack setxattr: {e}")
    return {'path': path, 'name': name, 'value': value, 'options': options, 'position': position}

def decode_listxattr(data: bytes) -> dict:
    """Decode listxattr method call"""
    offset = 1  # Skip method code
    path, offset = _decode_string(data, offset)
    return {'path': path}

def decode_removexattr(data: bytes) -> dict:
    """Decode removexattr method call"""
    offset = 1  # Skip method code
    path, offset = _decode_string(data, offset)
    name, offset = _decode_string(data, offset)
    return {'path': path, 'name': name}

def decode_mount(data: bytes) -> dict:
    """Decode mount method call"""
    offset = 1  # Skip method code
    share, offset = _decode_string(data, offset)
    return {'share': share}

# Dispatch tables
ENCODE_FUNCTIONS = {
    'read': encode_read,
    'write': encode_write,
    'chmod': encode_chmod,
    'chown': encode_chown,
    'create': encode_create,
    'destroy': encode_destroy,
    'getattr': encode_getattr,
    'statfs': encode_statfs,
    'mkdir': encode_mkdir,
    'open': encode_open,
    'release': encode_release,
    'access': encode_access,
    'readdir': encode_readdir,
    'readlink': encode_readlink,
    'rename': encode_rename,
    'rmdir': encode_rmdir,
    'link': encode_link,
    'symlink': encode_symlink,
    'truncate': encode_truncate,
    'unlink': encode_unlink,
    'utimens': encode_utimens,
    'exists': encode_exists,
    'get_mtime': encode_get_mtime,
    'get_ctime': encode_get_ctime,
    'getxattr': encode_getxattr,
    'setxattr': encode_setxattr,
    'listxattr': encode_listxattr,
    'removexattr': encode_removexattr,
    'mount': encode_mount,
}

DECODE_FUNCTIONS = {
    METHOD_CODES['read']: decode_read,
    METHOD_CODES['write']: decode_write,
    METHOD_CODES['chmod']: decode_chmod,
    METHOD_CODES['chown']: decode_chown,
    METHOD_CODES['create']: decode_create,
    METHOD_CODES['destroy']: decode_destroy,
    METHOD_CODES['getattr']: decode_getattr,
    METHOD_CODES['statfs']: decode_statfs,
    METHOD_CODES['mkdir']: decode_mkdir,
    METHOD_CODES['open']: decode_open,
    METHOD_CODES['release']: decode_release,
    METHOD_CODES['access']: decode_access,
    METHOD_CODES['readdir']: decode_readdir,
    METHOD_CODES['readlink']: decode_readlink,
    METHOD_CODES['rename']: decode_rename,
    METHOD_CODES['rmdir']: decode_rmdir,
    METHOD_CODES['link']: decode_link,
    METHOD_CODES['symlink']: decode_symlink,
    METHOD_CODES['truncate']: decode_truncate,
    METHOD_CODES['unlink']: decode_unlink,
    METHOD_CODES['utimens']: decode_utimens,
    METHOD_CODES['exists']: decode_exists,
    METHOD_CODES['get_mtime']: decode_get_mtime,
    METHOD_CODES['get_ctime']: decode_get_ctime,
    METHOD_CODES['getxattr']: decode_getxattr,
    METHOD_CODES['setxattr']: decode_setxattr,
    METHOD_CODES['listxattr']: decode_listxattr,
    METHOD_CODES['removexattr']: decode_removexattr,
    METHOD_CODES['mount']: decode_mount,
}

def decode_packet(data: bytes) -> Tuple[str, dict]:
    """
    Decode a packet and return (method_name, arguments)

    Args:
        data: The encoded packet data

    Returns:
        Tuple of (method_name, arguments_dict)

    Raises:
        ValueError: If the packet is invalid or method code is unknown
    """
    if not data:
        raise ValueError("Empty packet data")

    method_code = data[0]
    if method_code not in DECODE_FUNCTIONS:
        raise ValueError(f"Unknown method code: {method_code}")

    method_name = CODE_TO_METHOD[method_code]
    decode_func = DECODE_FUNCTIONS[method_code]
    args = decode_func(data)

    return method_name, args

def encode_method_call(method_name: str, *args, **kwargs) -> bytes:
    """
    Encode a method call with its arguments

    Args:
        method_name: Name of the method to call
        *args: Positional arguments
        **kwargs: Keyword arguments

    Returns:
        Encoded packet bytes

    Raises:
        ValueError: If method name is unknown
    """
    if method_name not in ENCODE_FUNCTIONS:
        raise ValueError(f"Unknown method: {method_name}")

    encode_func = ENCODE_FUNCTIONS[method_name]
    return encode_func(*args, **kwargs)
