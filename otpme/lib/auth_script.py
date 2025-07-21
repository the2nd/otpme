# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import script
from otpme.lib import config
from otpme.lib import backend
from otpme.lib.encoding.base import decode

from otpme.lib.exceptions import *

def run(script_uuid, options, auth_type, auth_user, auth_token, auth_group=None,
    auth_client=None, auth_client_ip=None, auth_pass=None, auth_otp=None,
    auth_challenge=None, auth_response=None, auth_nt_key=None,
    auth_trust_pass=None, auth_trust_pass_otp=None, script_type="auth_script",
    user=None, group=None, groups=None, **kwargs):
    """ Run auth script. """
    # Create dictionary with variables that will be passed to auth script.
    variables = {}
    variables["auth_type"] = auth_type
    variables["auth_user"] = auth_user
    variables["auth_token"] = auth_token
    variables["auth_group"] = auth_group
    variables["auth_client"] = auth_client
    variables["auth_client_ip"] = auth_client_ip
    variables["auth_pass"] = auth_pass
    variables["auth_otp"] = auth_otp
    variables["auth_challenge"] = auth_challenge
    variables["auth_response"] = auth_response
    variables["auth_nt_key"] = auth_nt_key
    variables["auth_trust_pass"] = auth_trust_pass
    variables["auth_trust_pass_otp"] = auth_trust_pass_otp

    result = backend.search(object_type="script",
                            attribute="uuid",
                            value=script_uuid,
                            return_type="instance",
                            realm=config.realm,
                            site=config.site)
    if not result:
        msg = (_("Unable to get auth script: %s") % script_uuid)
        raise OTPmeException(msg)

    s = result[0]
    script_path = s.rel_path
    _script = decode(s.script, "base64")
    script_signatures = s.signatures

    # Run auth script.
    script_returncode, \
    script_stdout, \
    script_stderr, \
    script_pid = script.run(script_type="auth_script",
                            script_path=script_path,
                            options=options,
                            script=_script,
                            variables=variables,
                            signatures=script_signatures,
                            user=user, group=group, groups=groups,
                            call=False)
    # Check request type.
    if auth_type == "mschap":
        # Check script exit status.
        if script_returncode == 0:
            # Check if auth script returned an nt_key.
            if script_stdout.startswith("NT_KEY:"):
                # Get NT key from command output.
                nt_key = script_stdout.replace("\n", "").split(" ")[1]
                return True, nt_key
            else:
                # Return false if we got no NT key from auth script.
                return False, False
        else:
            return False
    else:
        # Return depending on auth script returncode.
        if script_returncode == 0:
            return True
        else:
            return False

    # This point should never be reached.
    msg = (_("WARNING: You may have hit a BUG in auth_script.run(). "
                        "Authorization via script failed."))
    raise OTPmeException(msg)
