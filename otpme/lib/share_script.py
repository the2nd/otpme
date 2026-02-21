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

from otpme.lib import script
from otpme.lib import config
from otpme.lib import backend
from otpme.lib.encoding.base import decode

from otpme.lib.exceptions import *

def run(script_uuid, options, share_name, share_root, force_group=None,
    script_type="share_script", user=None, group=None, groups=None, **kwargs):
    """ Run share script. """
    # Create dictionary with variables that will be passed to share script.
    variables = {}
    variables["share_name"] = share_name
    variables["share_root"] = share_root
    if force_group:
        variables["force_group"] = force_group

    result = backend.search(object_type="script",
                            attribute="uuid",
                            value=script_uuid,
                            return_type="instance",
                            realm=config.realm,
                            site=config.site)
    if not result:
        msg = _("Unable to get share script: {}")
        msg = msg.format(script_uuid)
        raise OTPmeException(msg)

    s = result[0]
    script_path = s.rel_path
    _script = decode(s.script, "base64")
    script_signatures = s.signatures

    # Run share script.
    script_returncode, \
    script_stdout, \
    script_stderr, \
    script_pid = script.run(script_type="share_script",
                            script_path=script_path,
                            options=options,
                            script=_script,
                            variables=variables,
                            signatures=script_signatures,
                            user=user, group=group, groups=groups,
                            call=False)
    # Return depending on share script returncode.
    if script_returncode == 0:
        return True
    else:
        return False

    # This point should never be reached.
    msg = _("WARNING: You may have hit a BUG in share_script.run(). "
                        "Authorization via script failed.")
    raise OTPmeException(msg)
