# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from .get_class import get_class

REGISTER_BEFORE = []
REGISTER_AFTER = []

modules = [
        'otpme.lib.smartcard.fido2.fido2',
        'otpme.lib.smartcard.yubikey_hmac.yubikey_hmac',
        'otpme.lib.smartcard.yubikey_hotp.yubikey_hotp',
        'otpme.lib.smartcard.yubikey_gpg.yubikey_gpg',
        ]

def register():
    """ Register modules. """
    from ..register import _register_modules
    _register_modules(modules)
