# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import config
from otpme.lib import script
from otpme.lib import backend
from otpme.lib.encoding.base import decode

from otpme.lib.exceptions import *

logger = config.logger

def run(script_uuid, options, username, otp, phone_number=None,
    script_type=None, user=None, group=None, groups=None, **kwargs):
    """ Run push script to deliver OTP to user. """
    # Create dictionary with variables that will be passed to delivery script.
    variables = {}
    variables["username"] = username
    variables["otp"] = otp
    variables["phone_number"] = phone_number

    result = backend.search(object_type="script",
                            attribute="uuid",
                            value=script_uuid,
                            return_type="instance",
                            realm=config.realm,
                            site=config.site)
    if not result:
        msg = (_("Unable to get push script: %s") % script_uuid)
        raise OTPmeException(msg)

    s = result[0]
    script_path = s.rel_path
    _script = decode(s.script, "base64")
    script_signatures = s.signatures

    # Run push script.
    script_returncode, \
    script_stdout, \
    script_stderr, \
    script_pid = script.run(script_type="push_script",
                            script_path=script_path,
                            options=options,
                            script=_script,
                            variables=variables,
                            signatures=script_signatures,
                            user=user, group=group,
                            groups=groups,
                            call=False)
    # Make sure script output is string.
    script_stdout = script_stdout.decode()
    script_stderr = script_stderr.decode()
    # Check push script returncode.
    if script_returncode != 0:
        msg = (_("Push script failed: %s") % script_stderr)
        raise OTPmeException(msg)

    return True
