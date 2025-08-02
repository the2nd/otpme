# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import config

if config.typing_enabled:
    from strongtyping.strong_typing import match_class_typing
else:
    def match_class_typing(x):
        return x
if config.typing_enabled:
    from strongtyping.strong_typing import match_typing
else:
    def match_typing(x):
        return x
