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
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
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
    log_msg = _("Trying to resolve: {fqdn}", log=True)[1]
    log_msg = log_msg.format(fqdn=fqdn)
    config.logger.debug(log_msg)
    try:
        ip = socket.gethostbyname(fqdn)
    except:
        log_msg = _("Unable to resolve: {fqdn}", log=True)[1]
        log_msg = log_msg.format(fqdn=fqdn)
        config.logger.debug(log_msg)
        return False
    log_msg = _("Got IP from gethostbyname(): {ip}", log=True)[1]
    log_msg = log_msg.format(ip=ip)
    config.logger.debug(log_msg)
    return ip

def get_host_fqdn():
    """ Get host DNS FQDN. """
    # Try to get host FQDN.
    try:
        host_fqdn = socket.getfqdn()
    except Exception as e:
        msg = _("Unable to get host FQDN: {error}")
        msg = msg.format(error=e)
        raise OTPmeException(msg)
    return host_fqdn

def get_host_domainname():
    """ Get host DNS domain name. """
    # Try to get host FQDN.
    try:
        host_fqdn = get_host_fqdn()
    except Exception as e:
        msg = _("Unable to get host domainname: {error}")
        msg = msg.format(error=e)
        raise OTPmeException(msg)
    # Try to get search domain from host FQDN.
    domain = ".".join(host_fqdn.split(".")[1:])
    if len(domain) == 0:
        msg = _("Unable to get domain from host FQDN: {host_fqdn}")
        msg = msg.format(host_fqdn=host_fqdn)
        raise OTPmeException(msg)
    return domain

def get_otpme_site(domain):
    """
    Resolve OTPme realm/site via DNS.

    You need to add the following DNS SRV records:
        _otpme-realm    TXT "otpme.org"
        _otpme-site     TXT "berlin"

    """
    realm_record = f'_otpme-realm._tcp.{domain}'
    site_record = f'_otpme-site._tcp.{domain}'
    query_records = {
                    'realm' : realm_record,
                    'site'  : site_record,
                }

    result = {}
    for x in query_records:
        x_record = query_records[x]
        log_msg = _("Trying to resolve OTPme {type} via DNS: {record} (TXT)", log=True)[1]
        log_msg = log_msg.format(type=x, record=x_record)
        config.logger.debug(log_msg)
        try:
            answers = dns.resolver.query(x_record, 'TXT')
        except Exception as e:
            msg = _("Failed to query OTPme {type} via DNS: {error}")
            msg = msg.format(type=x, error=e)
            raise OTPmeException(msg)
        for a in answers:
            text = a.to_text().strip('"')
            result[x] = text
            log_msg = _("Got OTPme {type} from DNS: {text}", log=True)[1]
            log_msg = log_msg.format(type=x, text=text)
            config.logger.debug(log_msg)
            break
        if not x in result:
            msg = _("Unable to get OTPme {type} via DNS.")
            msg = msg.format(type=x)
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
        srv_record = f'_otpme-login._tcp.{domain}'
    elif daemon == "joind":
        srv_record = f'_otpme-join._tcp.{domain}'
    else:
        msg = _("Unsupported daemon: {daemon}")
        msg = msg.format(daemon=daemon)
        raise OTPmeException(msg)

    log_msg = _("Trying to resolve {daemon} socket URI via DNS: {record} (SRV)", log=True)[1]
    log_msg = log_msg.format(daemon=daemon, record=srv_record)
    config.logger.debug(log_msg)
    try:
        answers = dns.resolver.query(srv_record, 'SRV')
    except Exception as e:
        msg = _("Failed to query OTPme {daemon} attributes via DNS: {error}")
        msg = msg.format(daemon=daemon, error=e)
        raise OTPmeException(msg)
    for a in answers:
        text = a.to_text().strip('"')
        host = text.split()[-1].rstrip(".")
        port = text.split()[-2]
        socket_uri = f"tcp://{host}:{port}"
        log_msg = _("Got {daemon} socket URI from DNS: {uri}", log=True)[1]
        log_msg = log_msg.format(daemon=daemon, uri=socket_uri)
        config.logger.debug(log_msg)
        return socket_uri
    log_msg = _("Unable to get {daemon} address via SRV record, trying A record.", log=True)[1]
    log_msg = log_msg.format(daemon=daemon)
    config.logger.debug(log_msg)
    try:
        socket.gethostbyname(domain)
        port = config.default_ports[daemon]
        socket_uri = f"tcp://{domain}:{port}"
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
            msg = _("Unable to get MAC address of interface: {interface}")
            msg = msg.format(interface=iface)
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
            msg = _("IP '{address}' already assigned to interface '{interface}'.")
            msg = msg.format(address=address, interface=iface)
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
                msg = _("Floating IP '{floating_ip}' already assigned to interface '{interface}'.")
                msg = msg.format(floating_ip=floating_ip, interface=iface)
                raise AddressAlreadyAssigned(msg)

            _interface_network = ipaddr.IPNetwork(f"{ip}/{netmask}")

            if _interface_network.Contains(_floating_ip_network):
                phy_interface = iface
                floating_ip_netmask = netmask
                floating_ip_network = str(_interface_network.network)

    if not phy_interface:
        msg = _("No interface is configured for network of IP: {ip}")
        msg = msg.format(ip=floating_ip)
        raise OTPmeException(msg)

    floating_interface = phy_interface
    log_msg = _("Found interface '{interface}' for network '{network}/{netmask}'", log=True)[1]
    log_msg = log_msg.format(interface=floating_interface, network=floating_ip_network, netmask=floating_ip_netmask)
    config.logger.debug(log_msg)

    if ping:
        log_msg = _("Pinging address '{ip}'", log=True)[1]
        log_msg = log_msg.format(ip=floating_ip)
        config.logger.info(log_msg)
        ping_command = f"ping -w 1 -c 1 {floating_ip} > /dev/null 2>&1"
        response = os.system(ping_command)
        if response == 0:
            msg = _("Cannot add address '{ip}': already in use")
            msg = msg.format(ip=floating_ip)
            raise AddressAlreadyInUse(msg)

    log_msg = _("Adding address '{ip}/{netmask}' to interface '{interface}'", log=True)[1]
    log_msg = log_msg.format(ip=floating_ip, netmask=floating_ip_netmask, interface=floating_interface)
    config.logger.info(log_msg)

    ip_netmask = f"{floating_ip}/{floating_ip_netmask}"
    ifup_command = [
                    "ip",
                    "addr",
                    "add",
                    "dev",
                    floating_interface,
                    ip_netmask,
                    ]

    log_msg = _("Running: {command}", log=True)[1]
    log_msg = log_msg.format(command=' '.join(ifup_command))
    config.logger.debug(log_msg)

    pipe = Popen(ifup_command, stdout=PIPE, stderr=PIPE, shell=False)
    script_stdout, script_stderr = pipe.communicate()
    script_returncode = pipe.returncode

    if script_returncode != 0:
        msg = _("Error adding address '{ip}/{netmask}' to interface '{interface}': {error}")
        msg = msg.format(ip=floating_ip, netmask=floating_ip_netmask, interface=floating_interface, error=script_stderr)
        raise OTPmeException(msg)

    if gratuitous_arp:
        log_msg = _("Sending gratuitous ARP for floating IP: {ip} ({interface})", log=True)[1]
        log_msg = log_msg.format(ip=floating_ip, interface=floating_interface)
        config.logger.debug(log_msg)
        # Send gratuitous ARP.
        arp.send_gratuitous_arp(floating_interface, floating_ip)

    log_msg = _("Floating IP address configured successful.", log=True)[1]
    config.logger.debug(log_msg)

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
        log_msg = _("Deconfiguring floating interface '{interface}'", log=True)[1]
        log_msg = log_msg.format(interface=floating_interface)
        config.logger.debug(log_msg)

        ip_netmask = f"{floating_ip}/{floating_ip_netmask}"
        ifdown_command = [
                            "ip",
                            "addr",
                            "del",
                            "dev",
                            floating_interface,
                            ip_netmask,
                        ]

        log_msg = _("Running: {command}", log=True)[1]
        log_msg = log_msg.format(command=' '.join(ifdown_command))
        config.logger.debug(log_msg)

        pipe = Popen(ifdown_command, stdout=PIPE, stderr=PIPE, shell=False)
        script_stdout, script_stderr = pipe.communicate()
        script_returncode = pipe.returncode

        if script_returncode != 0:
            msg = _("Error removing address '{ip}/{netmask}' from interface '{interface}': {error}")
            msg = msg.format(ip=floating_ip, netmask=floating_ip_netmask, interface=floating_interface, error=script_stderr)
            raise OTPmeException(msg)

        log_msg = _("Floating IP address deconfigured successful.", log=True)[1]
        config.logger.debug(log_msg)
