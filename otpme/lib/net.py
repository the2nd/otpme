# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import socket
import ipaddress
import subprocess
import netifaces
import dns.resolver
from subprocess import PIPE
from subprocess import Popen

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module_name}")
        msg = msg.format(module_name=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import arp
from otpme.lib import config

from otpme.lib.exceptions import *

def is_ip(ip):
    """ Check if given IP is valid (IPv4 or IPv6). """
    try:
        ipaddress.ip_address(ip)
        return True
    except (ValueError, TypeError):
        return False

def is_ipv4(ip):
    """ Check if given IP is a valid IPv4 address. """
    try:
        return isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address)
    except (ValueError, TypeError):
        return False

def is_ipv6(ip):
    """ Check if given IP is a valid IPv6 address. """
    try:
        return isinstance(ipaddress.ip_address(ip), ipaddress.IPv6Address)
    except (ValueError, TypeError):
        return False

def normalize_ip(address):
    """ Normalize an IP address.

    Strips an optional [host]:port wrapper and unmaps IPv4-mapped IPv6
    addresses (e.g. '::ffff:10.0.0.1' -> '10.0.0.1'). Returns the input
    unchanged if it is not a parseable IP address.
    """
    if not address:
        return address
    s = str(address).strip()
    # Strip [ipv6]:port (or bare [ipv6]) wrapper per RFC 3986.
    if s.startswith("["):
        end = s.rfind("]")
        if end != -1:
            s = s[1:end]
    try:
        ip = ipaddress.ip_address(s)
    except (ValueError, TypeError):
        return s
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return str(ip.ipv4_mapped)
    return str(ip)

def format_socket_uri(scheme, address, port):
    """ Build a socket URI; brackets IPv6 literals per RFC 3986. """
    return f"{scheme}://{format_host_port(address, port)}"

def format_host_port(address, port):
    """ Build a 'host:port' string; brackets IPv6 literals. """
    if address and ":" in str(address):
        return f"[{address}]:{port}"
    return f"{address}:{port}"

def parse_socket_uri(socket_uri):
    """ Parse a socket URI.

    Returns (scheme, address, port) for tcp/udp URIs (port is int),
    or (scheme, path, None) for unix-socket URIs.
    Handles bracketed IPv6 literals: tcp://[2001:db8::1]:8080.
    """
    if "://" not in socket_uri:
        msg = _("Invalid socket URI: {uri}")
        msg = msg.format(uri=socket_uri)
        raise ValueError(msg)
    scheme, rest = socket_uri.split("://", 1)
    if scheme == "socket":
        return scheme, rest, None
    # tcp/udp: bracketed IPv6 literal?
    if rest.startswith("["):
        end = rest.find("]")
        if end == -1 or not rest[end+1:].startswith(":"):
            msg = _("Invalid socket URI: {uri}")
            msg = msg.format(uri=socket_uri)
            raise ValueError(msg)
        address = rest[1:end]
        port = int(rest[end+2:])
    else:
        # No brackets: rsplit on last ":" so v4 / hostname both work.
        if ":" not in rest:
            msg = _("Invalid socket URI: {uri}")
            msg = msg.format(uri=socket_uri)
            raise ValueError(msg)
        address, port_str = rest.rsplit(":", 1)
        port = int(port_str)
    return scheme, address, port

def get_socket_family(address):
    """ Pick the AF_* family from an address literal.

    IPv6 literals (containing ':') get AF_INET6, everything else AF_INET.
    The IPv6 wildcard '::' is treated as IPv6 dual-stack on the socket layer.
    """
    if address and ":" in str(address):
        return socket.AF_INET6
    return socket.AF_INET

def get_ip(fqdn, family=None):
    """ Resolve given FQDN via getaddrinfo().

    Returns the first address of the requested family. If no family is
    given, a v6 result is preferred over v4 (mirrors RFC 6724 ordering).
    Returns False on resolution failure.
    """
    log_msg = _("Trying to resolve: {fqdn}", log=True)[1]
    log_msg = log_msg.format(fqdn=fqdn)
    config.logger.debug(log_msg)
    try:
        infos = socket.getaddrinfo(fqdn, None,
                                    family if family is not None else 0,
                                    socket.SOCK_STREAM)
    except Exception:
        log_msg = _("Unable to resolve: {fqdn}", log=True)[1]
        log_msg = log_msg.format(fqdn=fqdn)
        config.logger.debug(log_msg)
        return False
    if not infos:
        return False
    # Prefer v6 unless caller pinned a family.
    if family is None:
        infos.sort(key=lambda r: 0 if r[0] == socket.AF_INET6 else 1)
    ip = infos[0][4][0]
    log_msg = _("Got IP from getaddrinfo(): {ip}", log=True)[1]
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
        raise OTPmeException(msg) from e
    return host_fqdn

def get_host_domainname():
    """ Get host DNS domain name. """
    # Try to get host FQDN.
    try:
        host_fqdn = get_host_fqdn()
    except Exception as e:
        msg = _("Unable to get host domainname: {error}")
        msg = msg.format(error=e)
        raise OTPmeException(msg) from e
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
            raise OTPmeException(msg) from e
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
        raise OTPmeException(msg) from e
    for a in answers:
        text = a.to_text().strip('"')
        host = text.split()[-1].rstrip(".")
        port = text.split()[-2]
        socket_uri = format_socket_uri("tcp", host, port)
        log_msg = _("Got {daemon} socket URI from DNS: {uri}", log=True)[1]
        log_msg = log_msg.format(daemon=daemon, uri=socket_uri)
        config.logger.debug(log_msg)
        return socket_uri
    log_msg = _("Unable to get {daemon} address via SRV record, trying A/AAAA record.", log=True)[1]
    log_msg = log_msg.format(daemon=daemon)
    config.logger.debug(log_msg)
    try:
        socket.getaddrinfo(domain, None, 0, socket.SOCK_STREAM)
        port = config.default_ports[daemon]
        socket_uri = format_socket_uri("tcp", domain, port)
        return socket_uri
    except Exception:
        return None

def query_dns(name, record="A"):
    result = dns.resolver.query(name, record)
    addresses = []
    for a in result:
        addresses.append(a.to_text().strip('"'))
    return addresses

def get_interfaces():
    """ Get all interface configs (IPv4 + IPv6).

    Each entry is a list of ``(ip, netmask)`` tuples. For IPv6 the
    netmask is normalized to a prefix-length string (e.g. ``"64"``);
    for IPv4 it stays in dotted-quad form (e.g. ``"255.255.255.0"``).
    Both forms work with ``ipaddress.ip_interface(f"{ip}/{netmask}")``.
    Zone suffixes (``%eth0``) on v6 link-local addresses are stripped.
    """
    interfaces = {}
    families = (netifaces.AF_INET, netifaces.AF_INET6)
    for interface in netifaces.interfaces():
        addresses = netifaces.ifaddresses(interface)
        entries = []
        for family in families:
            if family not in addresses:
                continue
            for address in addresses[family]:
                ip = address.get('addr')
                netmask = address.get('netmask', '')
                if not ip:
                    continue
                # netifaces returns v6 link-local with zone: 'fe80::1%eth0'
                if "%" in ip:
                    ip = ip.split("%", 1)[0]
                # netifaces returns v6 netmask as 'ffff:ffff:...::/64' --
                # keep the prefix length (everything after the last '/').
                if "/" in netmask:
                    netmask = netmask.rsplit("/", 1)[1]
                entries.append((ip, netmask))
        if entries:
            interfaces[interface] = entries
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

def configure_floating_ip(address, interface=None, gratuitous_arp=True, ping=False):
    """ Configure floating IP. """
    floating_ip = address
    floating_ip_network = None
    interfaces = get_interfaces()
    _floating_ip = ipaddress.ip_address(floating_ip)
    # Family-aware host route fallback.
    floating_ip_netmask = "128" if _floating_ip.version == 6 else "255.255.255.255"

    if not interface:
        for iface in interfaces:
            for x in interfaces[iface]:
                ip = x[0]
                netmask = x[1]
                try:
                    _interface_iface = ipaddress.ip_interface(f"{ip}/{netmask}")
                except (ValueError, TypeError):
                    continue

                # Skip mismatched address families.
                if _interface_iface.version != _floating_ip.version:
                    continue

                if _interface_iface.ip == _floating_ip:
                    msg = _("Floating IP '{floating_ip}' already assigned to interface '{interface}'.")
                    msg = msg.format(floating_ip=floating_ip, interface=iface)
                    raise AddressAlreadyAssigned(msg)

                if _floating_ip in _interface_iface.network:
                    interface = iface
                    floating_ip_netmask = netmask
                    floating_ip_network = str(_interface_iface.network.network_address)

    if not interface:
        msg = _("No interface is configured for network of IP: {ip}")
        msg = msg.format(ip=floating_ip)
        raise OTPmeException(msg)

    floating_interface = interface
    log_msg = _("Found interface '{interface}' for network '{network}/{netmask}'", log=True)[1]
    log_msg = log_msg.format(interface=floating_interface, network=floating_ip_network, netmask=floating_ip_netmask)
    config.logger.debug(log_msg)

    if ping:
        log_msg = _("Pinging address '{ip}'", log=True)[1]
        log_msg = log_msg.format(ip=floating_ip)
        config.logger.info(log_msg)
        response = subprocess.run(["ping", "-w", "1", "-c", "1", floating_ip],
                                  stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL).returncode
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
    floating_ip = address
    floating_interface = None
    floating_ip_netmask = None
    interfaces = get_interfaces()

    try:
        target = ipaddress.ip_address(floating_ip)
    except (ValueError, TypeError):
        target = None

    for iface in interfaces:
        for x in interfaces[iface]:
            ip = x[0]
            netmask = x[1]
            try:
                cur = ipaddress.ip_address(ip)
            except (ValueError, TypeError):
                continue
            if target is not None and cur == target:
                floating_interface = iface
                floating_ip_netmask = netmask
                break
        if floating_interface:
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
