# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import struct
import orjson

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import config
from otpme.lib.protocols.otpme_client import OTPmeClient1

from otpme.lib.exceptions import *

REGISTER_BEFORE = []
REGISTER_AFTER = []
PROTOCOL_VERSION = "OTPme-fs-1.0"

def register():
    config.register_otpme_protocol("fsd", PROTOCOL_VERSION)

class OTPmeFsP1(OTPmeClient1):
    """ Class that implements management client for protocol OTPme-fs-1.0. """
    def __init__(self, **kwargs):
        self.daemon = "fsd"
        self.name = PROTOCOL_VERSION
        # Get logger
        self.logger = config.logger
        super(OTPmeFsP1, self).__init__(self.daemon, **kwargs)

    def build_request(self, command, command_args={}, binary_data=None, **kwargs):
        """ Build request using orjson. """
        if command.startswith("fsop_"):
            packed_request = command_args['method_data']
        else:
            # Pack request with orjson (extremely fast JSON serialization)
            request_data = {
                    'command'       : command,
                    'command_args'  : command_args,
                    }
            packed_request = orjson.dumps(request_data)

        if binary_data is None:
            binary_data = b''

        # Simple binary header (8 bytes total):
        # - packed_data_length: 4 bytes (>I)
        # - binary_length: 4 bytes (>I)
        header_bytes = struct.pack('>II', len(packed_request), len(binary_data))

        request = header_bytes + packed_request + binary_data

        return request

    def decode_response(self, response, **kwargs):
        """ Decode OTPme response using orjson. """
        if isinstance(response, str):
            response = response.decode()

        # Parse simple binary header (8 bytes total):
        # - packed_data_length: 4 bytes (>I)
        # - binary_length: 4 bytes (>I)
        packed_data_length, binary_length = struct.unpack('>II', response[:8])

        # Extract data sections
        packed_start = 8
        packed_end = packed_start + packed_data_length
        binary_start = packed_end
        binary_end = binary_start + binary_length

        # Extract packed data and binary data
        packed_data = response[packed_start:packed_end]
        binary_data = response[binary_start:binary_end]

        # Unpack response with orjson (extremely fast JSON deserialization)
        try:
            response_data = orjson.loads(packed_data)
        except Exception as e:
            msg = ("Failed to decode orjson response: %s" % e)
            raise OTPmeException(msg)

        # Extract status code and data
        try:
            status_code = response_data['status_code']
            data = response_data['data']
        except KeyError as e:
            msg = "Invalid response: Missing field %s" % e
            raise OTPmeException(msg)

        return status_code, data, binary_data
