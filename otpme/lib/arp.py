# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import sys

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import config

from otpme.lib.exceptions import *

logger = config.logger

def send_gratuitous_arp(iface, ip):
    # Loading scapy module is slow so we import here.
    try:
        # Suppress warnings on module load.
        sys.stderr = None
        import scapy.all as arp_module
    except:
        try:
            import arprequest as arp_module
        except:
            msg = "Missing ARP module. Please install <scapy> or <arprequest>."
            raise OTPmeException(msg)
    finally:
        sys.stderr = sys.__stderr__
    if isinstance(iface, bytes):
        iface = iface.decode()
    if isinstance(ip, bytes):
        ip = ip.decode()
    if arp_module.__name__ == "scapy.all":
        return send_gratuitous_arp_scapy(iface, ip)
    elif arp_module.__name__ == "arprequest":
        return send_gratuitous_arp_arprequest(iface, ip)
    else:
        msg = "No ARP module available."
        raise OTPmeException(msg)

def send_gratuitous_arp_scapy(iface, ip):
    from scapy.all import ARP
    from scapy.all import Ether
    from scapy.all import sendp
    from otpme.lib import net
    # Broadcast MAC.
    BCAST_MAC = 'ff:ff:ff:ff:ff:ff'
    # Get interface MAC address.
    iface_mac = net.get_interface_mac(iface)
    # Build gratuitous ARP request.
    arp = ARP(psrc=ip, hwsrc=iface_mac, pdst=ip)
    arp_request = Ether(dst=BCAST_MAC) / arp
    # Send request and suppress output.
    sendp(arp_request, verbose=0)

def send_gratuitous_arp_arprequest(iface, ip):
    import arprequest
    # ARP type to send.
    arp_type = arprequest.ARP_GRATUITOUS
    # Build gratuitous ARP request.
    arp_request = arprequest.ArpRequest(ip, iface, arp_type=arp_type)
    # Send request.
    arp_request.request()
