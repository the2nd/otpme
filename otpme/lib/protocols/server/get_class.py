# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import importlib

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

def get_otpme_string(proto):
    otpme_string = proto.split("-")[0]
    return otpme_string

def get_proto_type(proto):
    """ Get protocol type from string. """
    proto_type = proto.split("-")[1]
    return proto_type

def get_proto_version(proto):
    """ Get protocol version from string. """
    proto_version = proto.split("-")[2].split(".")[0]
    return proto_version

def get_proto_name(proto):
    """ Get protocol name from string. """
    proto_type = get_proto_type(proto)
    proto_version = get_proto_version(proto)
    proto_name = "%s%s" % (proto_type, proto_version)
    return proto_name

def get_class_name(proto):
    """ Get protocol class from string. """
    otpme_string = get_otpme_string(proto)
    proto_type = get_proto_type(proto)
    proto_version = get_proto_version(proto)
    class_name = "%s%s%sP%s" % (otpme_string,
                            proto_type[0].upper(),
                            proto_type[1:],
                            proto_version)
    return class_name

def get_module(proto):
    """ Get protocol module by version string. """
    # Get protocol name.
    proto_name = get_proto_name(proto)
    # Build module path to proto module.
    proto_module_path = "otpme.lib.protocols.server.%s" % proto_name
    # Import protocol module.
    proto_module = importlib.import_module(proto_module_path)
    return proto_module

def get_class(proto):
    """ Get protocol class by version string. """
    # Get class name.
    class_name = get_class_name(proto)
    # Import protocol module.
    proto_module = get_module(proto)
    # Get protocol class.
    proto_class = getattr(proto_module, class_name)
    return proto_class
