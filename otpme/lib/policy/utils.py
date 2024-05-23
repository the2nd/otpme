# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import config
from otpme.lib.policy import get_class

def load_policy_modules():
    """ Load all policy modules """
    supported_policy_types = config.get_sub_object_types("policy")
    for policy_type in supported_policy_types:
        get_class(policy_type)
