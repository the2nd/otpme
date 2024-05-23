# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import config
from otpme.lib.resolver import get_class

def load_resolver_modules():
    """ Load all resolver modules """
    for resolver_type in config.get_sub_object_types("resolver"):
        get_class(resolver_type)
