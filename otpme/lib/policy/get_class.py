# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import importlib

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib.exceptions import *

def get_module(policy_type):
    """ Get policy module by type. """
    # Build module path to policy module.
    policy_module_path = "otpme.lib.policy.%s.%s" % (policy_type, policy_type)
    # Import policy module.
    policy_module = importlib.import_module(policy_module_path)
    return policy_module

def get_class(policy_type):
    """ Get policy class by type. """
    # Fix policy type name to match module path.
    policy_type = policy_type.replace("_", "")
    # Build policy class name from policy type.
    class_name = "%s%sPolicy" % (policy_type[0].upper(), policy_type[1:])
    # Get policy module.
    policy_module = get_module(policy_type)
    try:
        # Get policy class.
        policy_class = getattr(policy_module, class_name)
    except Exception as e:
        msg = (_("Error loading policy '%s': %s") % (class_name, e))
        raise OTPmeException(msg)
    return policy_class
