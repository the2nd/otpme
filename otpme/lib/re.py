# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
from otpme.lib.messages import error_message

# Check if re2 is available
# http://stackoverflow.com/questions/11190835/regular-expressions-in-python-unexpectedly-slow
try:
    from re2 import *
except Exception as e:
    from re import *
    error_message("WARNING: Unable to load module re2: %s" % e)
    error_message("WARNING: You may experience bad performance!!")
