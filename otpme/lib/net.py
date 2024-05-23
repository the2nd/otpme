# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import socket
import ipaddr
import netifaces
import dns.resolver
from subprocess import PIPE
from subprocess import Popen

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import arp
from otpme.lib import config

from otpme.lib.exceptions import *

def is_ip(ip):
    """ Check if given IP is valid. """
    try:
        socket.inet_aton(ip)
        return True
    except:
        return False

def get_ip(fqdn):
    """ Resolve given FQDN via gethostbyname(). """
    config.logger.debug("Trying to resolve: %s" % fqdn)
    try:
        ip = socket.gethostbyname(fqdn)
    except:
        config.logger.debug("Unable to resolve: %s")
        return False
    config.logger.debug("Got IP from gethostbyname(): %s" % ip)
    return ip

def get_host_fqdn():
    """ Get host DNS FQDN. """
    # Try to get host FQDN.
    try:
        host_fqdn = socket.getfqdn()
    except Exception as e:
        msg = (_("Unable to get host FQDN: %s") % e)
        raise OTPmeException(msg)
    return host_fqdn

def get_host_domainname():
    """ Get host DNS domain name. """
    # Try to get host FQDN.
    try:
        host_fqdn = get_host_fqdn()
    except Exception as e:
        msg = (_("Unable to get host domainname: %s") % e)
        raise OTPmeException(msg)
    # Try to get search domain from host FQDN.
    domain = ".".join(host_fqdn.split(".")[1:])
    if len(domain) == 0:
        msg = (_("Unable to get domain from host FQDN: %s") % host_fqdn)
        raise OTPmeException(msg)
    return domain

def get_otpme_site(domain):
    """
    Resolve OTPme realm/site via DNS.

    You need to add the following DNS SRV records:
        _otpme-realm    TXT "otpme.org"
        _otpme-site     TXT "berlin"

    """
    realm_record = '_otpme-realm._tcp.%s' % domain
    site_record = '_otpme-site._tcp.%s' % domain
    query_records = {
                    'realm' : realm_record,
                    'site'  : site_record,
                }

    result = {}
    for x in query_records:
        x_record = query_records[x]
        config.logger.debug("Trying to resolve OTPme %s via DNS: %s (TXT)"
                    % (x, x_record))
        try:
            answers = dns.resolver.query(x_record, 'TXT')
        except Exception as e:
            msg = ("Failed to query OTPme %s via DNS: %s" % (x, e))
            raise OTPmeException(msg)
        for a in answers:
            text = a.to_text().strip('"')
            result[x] = text
            config.logger.debug("Got OTPme %s from DNS: %s" % (x, text))
            break
        if not x in result:
            msg = ("Unable to get OTPme %s via DNS.")
            raise OTPmeException(msg)
    return result

def get_daemon_uri(daemon, domain):
    """
    Resolve OTPme daemon socket URI via DNS.

    Currently we support resolving of authd and joind socket URIs.

    You need to add the following DNS SRV records:
        _otpme-login    SRV 10 1 2020 login.otpme.org.
        _otpme-join     SRV 10 1 2024 login.otpme.org.

    """
    if daemon == "authd":
        srv_record = '_otpme-login._tcp.%s' % domain
    elif daemon == "joind":
        srv_record = '_otpme-join._tcp.%s' % domain
    else:
        msg = ("Unsupported daemon: %s" % daemon)
        raise OTPmeException(msg)

    config.logger.debug("Trying to resolve %s socket URI via DNS: %s (SRV)"
                % (daemon, srv_record))
    try:
        answers = dns.resolver.query(srv_record, 'SRV')
    except Exception as e:
        msg = ("Failed to query OTPme %s attributes via DNS: %s"
                % (daemon, e))
        raise OTPmeException(msg)
    for a in answers:
        text = a.to_text().strip('"')
        host = text.split()[-1].rstrip(".")
        port = text.split()[-2]
        socket_uri = "tcp://%s:%s" % (host, port)
        config.logger.debug("Got %s socket URI from DNS: %s"
                    % (daemon, socket_uri))
        return socket_uri
    config.logger.debug("Unable to get %s address via SRV record, trying A "
                "record..." % daemon)
    try:
        socket.gethostbyname(domain)
        port = config.default_ports[daemon]
        socket_uri = "tcp://%s:%s" % (domain, port)
        return socket_uri
    except:
        return None

def query_dns(name, record="A"):
    result = dns.resolver.query(name, record)
    addresses = []
    for a in result:
        addresses.append(a.to_text().strip('"'))
    return addresses

def get_interfaces():
    """ Get all interface configs. """
    interfaces = {}
    for interface in netifaces.interfaces():
        addresses = netifaces.ifaddresses(interface)
        if not 2 in addresses:
            continue
        interfaces[interface] = []
        for address in addresses[2]:
            ip = address['addr']
            netmask = address['netmask']
            interfaces[interface].append((ip, netmask))
    return interfaces

def get_interface_mac(iface):
    iface_data = netifaces.ifaddresses(iface)
    if not netifaces.AF_LINK in iface_data:
        if ":" not in iface:
            msg = "Unable to get MAC address of interface: %s" % iface
            raise OTPmeException(msg)
        iface = iface.split(":")[0]
        return get_interface_mac(iface)
    iface_mac = iface_data[netifaces.AF_LINK][0]['addr']
    return iface_mac

def check_for_ip(address):
    """ Check if IP is already assigned. """
    interfaces = get_interfaces()
    for iface in interfaces:
        for x in interfaces[iface]:
            ip = x[0]
            if ip != address:
                continue
            msg = (_("IP '%s' already assigned to interface "
                    "'%s'.") % (address, iface))
            raise AddressAlreadyAssigned(msg)

def configure_floating_ip(address, gratuitous_arp=True, ping=False):
    """ Configure floating IP. """
    phy_interface = None
    floating_ip = address
    floating_ip_netmask = None
    floating_ip_network = None
    interfaces = get_interfaces()
    _floating_ip_network = ipaddr.IPAddress(floating_ip)

    for iface in interfaces:
        for x in interfaces[iface]:
            ip = x[0]
            netmask = x[1]
            if ip == floating_ip:
                msg = (_("Floating IP '%s' already assigned to interface "
                        "'%s'.") % (floating_ip, iface))
                raise AddressAlreadyAssigned(msg)

            _interface_network = ipaddr.IPNetwork("%s/%s" % (ip, netmask))

            if _interface_network.Contains(_floating_ip_network):
                phy_interface = iface
                floating_ip_netmask = netmask
                floating_ip_network = str(_interface_network.network)

    if not phy_interface:
        msg = (_("No interface is configured for network of IP: %s")
                % floating_ip)
        raise OTPmeException(msg)

    floating_interface = phy_interface
    config.logger.debug("Found interface '%s' for network '%s/%s'"
                % (floating_interface, floating_ip_network, floating_ip_netmask))

    if ping:
        config.logger.info("Pinging address '%s'" % floating_ip)
        ping_command = "ping -w 1 -c 1 %s > /dev/null 2>&1" % floating_ip
        response = os.system(ping_command)
        if response == 0:
            msg = (_("Cannot add address '%s': already in use") % floating_ip)
            raise AddressAlreadyInUse(msg)

    msg = ("Adding address '%s/%s' to interface '%s'"
        % (floating_ip, floating_ip_netmask, floating_interface))
    config.logger.info(msg)

    ip_netmask = "%s/%s" % (floating_ip, floating_ip_netmask)
    ifup_command = [
                    "ip",
                    "addr",
                    "add",
                    "dev",
                    floating_interface,
                    ip_netmask,
                    ]

    config.logger.debug("Running: %s" % " ".join(ifup_command))

    pipe = Popen(ifup_command, stdout=PIPE, stderr=PIPE, shell=False)
    script_stdout, script_stderr = pipe.communicate()
    script_returncode = pipe.returncode

    if script_returncode != 0:
        msg = (_("Error adding address '%s/%s' to interface '%s': %s")
                % (floating_ip, floating_ip_netmask,
                floating_interface, script_stderr))
        raise OTPmeException(msg)

    if gratuitous_arp:
        msg = ("Sending gratuitous ARP for floating IP: %s (%s)"
                % (floating_ip, floating_interface))
        config.logger.debug(msg)
        # Send gratuitous ARP.
        arp.send_gratuitous_arp(floating_interface, floating_ip)

    config.logger.debug("Floating IP address configured successful.")

def deconfigure_floating_ip(address):
    """ Deconfigure floating IP. """
    floating_interface = None
    floating_ip = address
    interfaces = get_interfaces()

    for iface in interfaces:
        for x in interfaces[iface]:
            ip = x[0]
            netmask = x[1]
            if ip == floating_ip:
                floating_interface = iface
                floating_ip_netmask = netmask
                break

    if floating_interface:
        msg = ("Deconfiguring floating interface '%s'" % floating_interface)
        config.logger.debug(msg)

        ip_netmask = "%s/%s" % (floating_ip, floating_ip_netmask)
        ifdown_command = [
                            "ip",
                            "addr",
                            "del",
                            "dev",
                            floating_interface,
                            ip_netmask,
                        ]

        config.logger.debug("Running: %s" % " ".join(ifdown_command))

        pipe = Popen(ifdown_command, stdout=PIPE, stderr=PIPE, shell=False)
        script_stdout, script_stderr = pipe.communicate()
        script_returncode = pipe.returncode

        if script_returncode != 0:
            msg = (_("Error removing address '%s/%s' from interface '%s': %s")
                    % (floating_ip, floating_ip_netmask,
                    floating_interface, script_stderr))
            raise OTPmeException(msg)

        config.logger.debug("Floating IP address deconfigured successful.")
