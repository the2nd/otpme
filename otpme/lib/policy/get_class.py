# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import importlib

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {__name__}")
        msg = msg.format(__name__=__name__)
        print(msg)
except:
    pass

from otpme.lib.exceptions import *

def get_module(policy_type):
    """ Get policy module by type. """
    # Build module path to policy module.
    policy_module_path = f"otpme.lib.policy.{policy_type}.{policy_type}"
    # Import policy module.
    policy_module = importlib.import_module(policy_module_path)
    return policy_module

def get_class(policy_type):
    """ Get policy class by type. """
    # Fix policy type name to match module path.
    policy_type = policy_type.replace("_", "")
    # Build policy class name from policy type.
    class_name = f"{policy_type[0].upper()}{policy_type[1:]}Policy"
    # Get policy module.
    policy_module = get_module(policy_type)
    try:
        # Get policy class.
        policy_class = getattr(policy_module, class_name)
    except Exception as e:
        msg = _("Error loading policy '{}': {}")
        msg = msg.format(class_name, e)
        raise OTPmeException(msg)
    return policy_class
