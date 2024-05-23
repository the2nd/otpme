# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import sys
import bz2
import zlib
import gzip
import magic
import struct
import lz4.frame

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib.exceptions import *

SUPPORTED_COMPRESSIONS = {
                        'GZIP'  : [1, 2, 3, 4, 5, 6, 7, 8, 9],
                        'BZIP2' : [1, 2, 3, 4, 5, 6, 7, 8, 9],
                        'ZLIB'  : [1, 2, 3, 4, 5, 6, 7, 8, 9],
                        }
BZIP2_MIMETYPES = ['application/x-bzip2']
GZIP_MIMETYPES = ['application/x-gzip', 'application/gzip']

REGISTER_BEFORE = []
REGISTER_AFTER = ["otpme.lib.encoding.base"]

def register():
    """ Register compression types. """
    cmodule = sys.modules[__name__]
    from otpme.lib import config
    for compression in SUPPORTED_COMPRESSIONS:
        levels = SUPPORTED_COMPRESSIONS[compression]
        config.register_compression_type(compression, cmodule)
        for x in levels:
            level = "%s_%s" % (compression, x)
            config.register_compression_type(level, cmodule)

def get_compression_type(filename):
    """ Get compression type of file. """
    compression = None
    file_type = magic.from_file(filename, mime=True)
    if file_type in GZIP_MIMETYPES:
        compression = "GZIP"
    elif file_type in BZIP2_MIMETYPES:
        compression = "BZIP2"
    elif file_type == "application/x-lz4":
        compression = "lz4"
    elif file_type == "application/zlib":
        compression = "zlib"
    elif file_type == "application/octet-stream":
        x_file_type = magic.from_file(filename, mime=False)
        if x_file_type.startswith("lzop compressed data"):
            compression = "LZO"
    if not compression:
        msg = "Unable to detect file compression."
        raise OTPmeException(msg)
    return compression

def get_uncompressed_size(filename):
    """ Get uncompressed size of gzip file. """
    compression = get_compression_type(filename)
    if compression != "GZIP":
        msg = "Unsupported compression: %s" %compression
        raise UnsupportedCompressionType(msg)
    # https://stackoverflow.com/questions/1704458/get-uncompressed-size-of-a-gz-file-in-python
    with open(filename, 'rb') as f:
        f.seek(-4, 2)
        return struct.unpack('I', f.read(4))[0]
    #fileobj = open(filename, 'r')
    ##fileobj.seek(-8, 2)
    #fileobj.seek(0, 2)
    #fileobj.seek(-3, 2)
    ## Read crc32.
    #gzip.read32(fileobj)
    ## Read size.
    #isize = gzip.read32(fileobj)
    #fileobj.close()
    #return isize

def compress(data, compression, level=None):
    """ Compress given data. """
    if not isinstance(data, bytes):
        data = data.encode()
    if compression == "gzip":
        if level is None:
            level = 9
        compressed_data = gzip.compress(data, compresslevel=level)

    elif compression == "lz4":
        compressed_data = lz4.frame.compress(data)

    elif compression == "zlib":
        if level is None:
            level = 6
        compressed_data = zlib.compress(data, level)

    elif compression == "bzip":
        if level is None:
            level = 9
        compressed_data = bz2.compress(data, level)
    else:
        msg = (_("Unknown compression: %s") % compression)
        raise OTPmeException(msg)

    return compressed_data

def decompress(data, compression):
    """ Decompress given data. """
    if compression == "gzip":
        decompressed_data = gzip.decompress(data)
    elif compression == "lz4":
        decompressed_data = lz4.frame.decompress(data)
    elif compression == "zlib":
        decompressed_data = zlib.decompress(data)
    elif compression == "bzip":
        decompressed_data = bz2.decompress(data)
    else:
        msg = (_("Unknown compression: %s") % compression)
        raise OTPmeException(msg)
    # Try to return string.
    try:
        decompressed_data = decompressed_data.decode()
    except ValueError:
        pass
    return decompressed_data
