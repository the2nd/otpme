# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {}")
        msg = msg.format(__name__)
        print(msg)
except:
    pass

from otpme.lib import config
from otpme.lib import otpme_acl

logger = config.logger
default_callback = config.get_callback()

def get_extension(extension):
    """ Get OTPme extension class. """
    import importlib
    module_path = f"otpme.lib.extensions.{extension}.{extension}"
    try:
        # import extension module
        extension_module = importlib.import_module(module_path)
        extension_class = getattr(extension_module, 'OTPmeExtension')
        extension = extension_class()
    except Exception as e:
        config.raise_exception()
        msg = _("Error loading extension '{}': {}")
        msg = msg.format(extension, e)
        raise Exception(msg)
    return extension

def get_acls(object_type):
    """ Get valid ACLs for the given object type. """
    acls = []
    for i in config.extensions:
        e = get_extension(i)
        acls += e.get_acls(object_type)
    return acls

def get_value_acls(object_type):
    """ Get valid value ACLs for the given object type. """
    value_acls = {}
    for i in config.extensions:
        e = get_extension(i)
        e.load_schema()
        x = e.get_value_acls(object_type)
        value_acls = otpme_acl.merge_value_acls(value_acls, x)
    return value_acls

def preload_extensions():
    """ Preload all OTPme extensions. """
    log_msg = _("Preloading extensions...", log=True)[1]
    logger.debug(log_msg)
    extensions = load_extensions(config.extensions)
    for e in extensions:
        e.preload()
    log_msg = _("Preloaded {len(config.extensions)} extensions.", log=True)[1]
    logger.debug(log_msg)

def load_schemas():
    """ Load schema files of all OTPme extensions. """
    from otpme.lib import config
    extensions = load_extensions(config.extensions)
    for e in extensions:
        e.load_schema()

def load_extensions(extensions, callback=default_callback):
    """ Load extensions and handle dependencies. """
    _extensions = {}
    for e in extensions:
        if e != "":
            extension = get_extension(e)
            if extension:
                _extensions[e] = extension

    if len(_extensions) == 0:
        return _extensions

    ext_loaded = []
    extensions_loaded = []
    load_extension = True
    while True:
        for e in dict(_extensions):
            _e = _extensions[e]
            for dep_ext in _e.need_extensions:
                _dep_ext = _extensions[dep_ext]
                if e in _dep_ext.need_extensions:
                    msg, log_msg = _("Detected dependency loop: {} <> {}", log=True)
                    msg = msg.format(e, dep_ext)
                    # FIXME: log user messages?
                    #log_msg = log_msg.format(e, dep_ext)
                    #logger.critical(log_msg)
                    return callback.error(msg)
                if not dep_ext in ext_loaded:
                    load_extension = False
                    if not dep_ext in _extensions:
                        msg, log_msg = _("Cannot load extension '{}' which depends on extension '.", log=True)
                        msg = msg.format(e, dep_ext)
                        log_msg = log_msg.format(e, dep_ext)
                        logger.critical(log_msg)
                        callback.send(msg)
                        _extensions.pop(e)

            if load_extension:
                if not _e.name in ext_loaded:
                    ext_loaded.append(_e.name)
                    extensions_loaded.append(_e)
            else:
                load_extension = True

        if len(_extensions) == len(ext_loaded):
            break

    return extensions_loaded
