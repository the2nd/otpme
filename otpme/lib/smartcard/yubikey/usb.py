# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import fcntl
import subprocess

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import config

logger = config.logger

# THIS STUFF IS CURRENTLY NOT USED!!!!

# https://gist.github.com/PaulFurtado/fce98aef890469f34d51

# Equivalent of the _IO('U', 20) constant in the linux kernel.
USBDEVFS_RESET = ord('U') << (4*2) | 20

def get_yubikey():
    """
        Gets the devfs path to a yubikey by scraping the output
        of the lsusb command.
        The lsusb command outputs a list of USB devices attached to a computer
        in the format:
            Bus 005 Device 018: ID 1050:0111 Yubico.com
        The devfs path to these devices is:
            /dev/bus/usb/<busnum>/<devnum>
        So for the above device, it would be:
            /dev/bus/usb/002/009
        This function generates that path.
    """
    proc = subprocess.Popen(['lsusb'], stdout=subprocess.PIPE)
    out = proc.communicate()[0]
    lines = out.split('\n')
    for line in lines:
        if 'Yubico.com' in line:
            parts = line.split()
            bus = parts[1]
            dev = parts[3][:3]
            return '/dev/bus/usb/%s/%s' % (bus, dev)


def send_reset(dev_path):
    """
        Sends the USBDEVFS_RESET IOCTL to a USB device.
        dev_path - The devfs path to the USB device (under /dev/bus/usb/)
                   See get_yubikey for example of how to obtain this.
    """
    logger.debug("Sending USB reset command to yubikey...")
    fd = os.open(dev_path, os.O_WRONLY)
    try:
        fcntl.ioctl(fd, USBDEVFS_RESET, 0)
    finally:
        os.close(fd)


def reset_yubikey():
    """
        Finds a yubikey and sends a USB reset command.
    """
    yubikey_dev = get_yubikey()
    if yubikey_dev:
        send_reset(yubikey_dev)
        return True
    else:
        return False

