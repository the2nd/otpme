# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except:
    pass

from otpme.lib.exceptions import *

def detect_smartcard(sc_types=None, detect_only=False, print_devices=False):
    """ Try to find a connected smartcard """
    from otpme.lib import config
    from otpme.lib.smartcard import get_class
    logger = config.logger
    logger.debug("Starting smartcard detection...")
    smartcard = None
    supported_smartcards = config.get_supported_smartcards()
    for s in supported_smartcards:
        try:
            smartcard_class = get_class(s)
        except ImportError as e:
            msg = _("Missing smartcard support: {error}")
            msg = msg.format(error=e)
            logger.debug(msg)
        except Exception as e:
            msg = _("Problem loading smartcard module '{module}': {error}")
            msg = msg.format(module=s, error=e)
            logger.warning(msg)
        # Get smartcard instance.
        smartcard = smartcard_class(autodetect=False)
        # Check if we have to search for smartcard of this type.
        search_smartcard = True
        if sc_types:
            search_smartcard = False
            for sc_type in sc_types:
                if sc_type in smartcard.otpme_auth_types:
                    search_smartcard = True
                    break
        if not search_smartcard:
            smartcard = None
            continue
        msg = _("Searching for smartcard: {type}")
        msg = msg.format(type=s)
        logger.debug(msg)
        if print_devices:
            print(msg)
        try:
            smartcard.detect(print_devices=print_devices)
            msg = _("Detected smartcard: {type}")
            msg = msg.format(type=smartcard.type)
            logger.debug(msg)
            # currently we only support one smartcard at a time
            if not detect_only:
                break
        except NoSmartcardFound:
            smartcard = None
    return smartcard
