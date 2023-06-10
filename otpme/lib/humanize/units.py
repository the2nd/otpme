# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
# Distributed under the terms of the GNU General Public License v2
import os
import humanize

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

unit_mapping = {
        's'     : 1,
        'm'     : 60,
        'h'     : 3600,
        'D'     : 86400,
        'W'     : 604800,
        'M'     : 2592000,
        'Y'     : 31536000,
        }

mapping_order = [ 'Y', 'M', 'W', 'D', 'h', 'm', 's' ]

def time2int(value, time_unit="s"):
    """ Convert human readable time string to int(). """
    if len(str(value)) > 1:
        val_unit = str(value)[-1]
        val = int(str(value)[:-1])
    else:
        val_unit = time_unit
        val = int(value)
    if val_unit in [ "0", "1", "2", "3", "4", "5", "6", "7", "8", "9" ]:
        val_unit = time_unit
        val = int(value)
    if not val_unit in unit_mapping:
        raise Exception(_("Unknown time unit: %s") % val_unit)
    multiplier = unit_mapping[val_unit]
    divider = unit_mapping[time_unit]
    result = int(float((val * multiplier)) / divider)
    return result


def int2time(value, time_unit="s", exact_only=True):
    """ Convert time as int() to human readable time string. """
    result = []
    remain = 0
    result_unit = None
    multiplier = unit_mapping[time_unit]
    val = float(int(value) * multiplier)
    for x in mapping_order:
        divider = unit_mapping[x]
        r = float(val / divider)
        if exact_only:
            if not r.is_integer():
                continue
            if not remain or int(r) < remain:
                remain = int(r)
                if remain == 0:
                    result_unit = time_unit
                else:
                    result_unit = x
                result.append("%s%s" % (remain, result_unit))
                break
        else:
            r = int(r)
            if r < 1:
                continue
            val = int(val - (divider * r))
            time_str = "%s%s" % (r, x)
            result.append(time_str)
    if not result:
        result = ["0s"]
    return result


def int2size(value):
    """ Convert size as int() to human result size string. """
    result = humanize.naturalsize(value, gnu=True)
    return result
