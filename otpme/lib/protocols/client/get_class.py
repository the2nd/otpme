# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import importlib

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

def get_class(proto):
    """ Get protocol class by version string. """
    # build protocol class name from protocol version string
    otpme_string = proto.split("-")[0]
    proto_type = proto.split("-")[1]
    proto_version = proto.split("-")[2].split(".")[0]
    class_name = "%s%s%sP%s" % (otpme_string,
                                proto_type[0].upper(),
                                proto_type[1:],
                                proto_version)

    proto_name = "%s%s" % (proto_type, proto_version)

    # build module path to proto module
    proto_module_path = "otpme.lib.protocols.client.%s" % proto_name
    # import protocol module
    proto_module = importlib.import_module(proto_module_path)
    # get protocol class
    proto_class = getattr(proto_module, class_name)
    return proto_class
