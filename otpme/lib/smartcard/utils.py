# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

def detect_smartcard(sc_types=None):
    """ Try to find a connected smartcard """
    from otpme.lib import config
    from otpme.lib.smartcard import get_class
    logger = config.logger
    logger.debug("Starting smartcard detection...")
    smartcard = None
    supported_smartcards = config.get_supported_smartcards()
    for s in supported_smartcards:
        logger.debug("Searching for smartcard: %s" % s)
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
        try:
            smartcard.detect()
            logger.debug("Detected smartcard: %s" % smartcard.type)
            # currently we only support one smartcard at a time
            break
        except:
            smartcard = None
    return smartcard
