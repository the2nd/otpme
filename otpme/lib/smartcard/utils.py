# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
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
            logger.debug("Missing smartcard support: %s" % e)
        except Exception as e:
            msg = ("Problem loading smartcard module '%s': %s" % (s, e))
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
        msg = "Searching for smartcard: %s" % s
        logger.debug(msg)
        if print_devices:
            print(msg)
        try:
            smartcard.detect(print_devices=print_devices)
            logger.debug("Detected smartcard: %s" % smartcard.type)
            # currently we only support one smartcard at a time
            if not detect_only:
                break
        except NoSmartcardFound:
            smartcard = None
    return smartcard
