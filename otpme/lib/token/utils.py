# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except:
    pass

from otpme.lib import config
from otpme.lib.token import get_class

def load_token_modules():
    """ Load all token modules. """
    for token_type in config.get_sub_object_types("token"):
        mod_name = token_type.replace("-", "_")
        get_class(mod_name)
