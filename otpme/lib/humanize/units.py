# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import humanize
import datetime

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib.exceptions import *

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

def string2unixtime(date_string, start_time):
    """ Get unix time from string. """
    hour = None
    minute = None
    day = None
    month = None
    year = None
    if date_string.startswith("+"):
        x = date_string.replace("+", "")
        seconds = time2int(x)
        if seconds == 0:
            msg = "Invalid time: %s" % date_string
            raise OTPmeException(msg)
        start_time = datetime.datetime.fromtimestamp(start_time)
        epoch = start_time + datetime.timedelta(seconds=seconds)
    else:
        for x in date_string.split():
            if len(x.split("/")) == 3:
                month = int(x.split("/")[0])
                day = int(x.split("/")[1])
                year = int(x.split("/")[2])
            elif len(x.split("-")) == 3:
                year = int(x.split("-")[0])
                month = int(x.split("-")[1])
                day = int(x.split("-")[2])
            elif len(x.split(".")) == 3:
                day = int(x.split(".")[0])
                month = int(x.split(".")[1])
                year = int(x.split(".")[2])
            elif len(x.split(":")) == 2:
                hour = int(x.split(":")[0])
                minute = int(x.split(":")[1])
            else:
                msg = (_("Unknown date string: %s") % date_string)
                raise OTPmeException(msg)

        if year is None:
            raise OTPmeException("Missing 'year'")
        if month is None:
            raise OTPmeException("Missing 'month'")
        if hour is None:
            raise OTPmeException("Missing 'hour'")
        if minute is None:
            raise OTPmeException("Missing 'minute'")

        if len(str(year)) < 4:
            raise OTPmeException(_("Unknown year: %s") % year)

        epoch = datetime.datetime(year, month, day, hour, minute)

    epoch = float(epoch.strftime("%s"))

    return epoch
