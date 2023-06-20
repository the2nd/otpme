# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
# Distributed under the terms of the GNU General Public License v2
import datetime
now = datetime.datetime.now()

__project_name__ = "otpme"
__project_url__ = "http://www.otpme.org"
__copyright__ = "Copyright 2014-2022 the2nd <the2nd@otpme.org>"
__project_description__ = "OTPme: A flexible One-Time-Password system."
__author__ = "the2nd"
__email__ = "the2nd@otpme.org"
__credits__ = []
__license__ = "GPLv2"
__version__ = "0.3.0a39"
__status__ = "Development Status :: 3 - Alpha"
# In future versions :D
#__status__ = "Development Status :: 4 - Beta"
#__status__ = "Development Status :: 5 - Production/Stable"
__pkg_name__ = __project_name__
__maintainer__ = __author__
__author_email__  = __email__
__maintainer_email__  = __email__
__release_date__ = "%s.%s.%s" % (now.strftime('%d'),
                                now.strftime('%m'),
                                now.strftime('%y'))
