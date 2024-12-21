# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from .get_class import get_class
from .get_class import get_module

REGISTER_BEFORE = []
REGISTER_AFTER = []

modules = [
        'otpme.lib.token.hotp.hotp',
        'otpme.lib.token.link.link',
        'otpme.lib.token.motp.motp',
        'otpme.lib.token.otp_push.otp_push',
        'otpme.lib.token.password.password',
        'otpme.lib.token.script_otp.script_otp',
        'otpme.lib.token.script_static.script_static',
        'otpme.lib.token.ssh.ssh',
        'otpme.lib.token.totp.totp',
        'otpme.lib.token.fido2.fido2',
        'otpme.lib.token.yubikey_hmac.yubikey_hmac',
        ]

def register():
    """ Register modules. """
    from ..register import _register_modules
    _register_modules(modules)
