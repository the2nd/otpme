# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except Exception:
    pass

from . import register_cmd_help

def register():
    register_cmd_help(command="inventory", help_dict=cmd_help)

cmd_help = {
    '_need_command'             : True,
    '_include_global_opts'      : True,
    '_usage_help'               : _("Usage: otpme-inventory {command} [options]"),

    'show'    : {
                    '_cmd_usage_help' : _('Usage: otpme-inventory show {host}'),
                    'cmd'   :   '<host>',
                    '_help' :   {
                                    'cmd'                       : _('Show the system, kernel and OTPme version of a host, whether it waits for a reboot and how many packages it has.'),
                                },
                },

    'packages'    : {
                    '_cmd_usage_help' : _('Usage: otpme-inventory packages [--filter <pattern>] {host}'),
                    'cmd'   :   '--filter :package_filter: <host>',
                    '_help' :   {
                                    'cmd'                       : _('List the packages of a host.'),
                                    '--filter <pattern>'        : _('Only packages whose name matches (e.g. "python3-*").'),
                                },
                },

    'hardware'    : {
                    '_cmd_usage_help' : _('Usage: otpme-inventory hardware {host}'),
                    'cmd'   :   '<host>',
                    '_help' :   {
                                    'cmd'                       : _('Show the hardware of a host.'),
                                },
                },

    'search'    : {
                    '_cmd_usage_help' : _('Usage: otpme-inventory search [--host <host>] [--os-version <version>] [--kernel <kernel>] [--otpme-version <version>] [--reboot-required] [--hardware <expression>] [--upgradable] [package]'),
                    'cmd'   :   '--host :host: --os-version :os_version: --kernel :kernel: --otpme-version :otpme_version: --reboot-required :reboot_required=True: --hardware :hardware: --upgradable :upgradable=True: [package]',
                    '_help' :   {
                                    'cmd'                       : _('Search hosts by package (e.g. openssl, "openssl=3.0.*"), OS version, kernel, OTPme version, reboot or hardware.'),
                                    '--upgradable'              : _('Only packages of which the system of the host offers a newer version.'),
                                    '--host <host>'             : _('Only this host (e.g. to search its packages).'),
                                    '--os-version <version>'    : _('Only hosts with this OS version (e.g. debian-12).'),
                                    '--kernel <kernel>'         : _('Only hosts running this kernel (e.g. "6.1.0-3*").'),
                                    '--otpme-version <version>' : _('Only hosts running this OTPme version (e.g. "0.3.0a28*").'),
                                    '--reboot-required'         : _('Only hosts that have to be rebooted.'),
                                    '--hardware <expression>'   : _('Only hosts whose hardware matches (e.g. serial=ABC123, "memory<8G").'),
                                },
                },

    'systems'    : {
                    '_cmd_usage_help' : _('Usage: otpme-inventory systems'),
                    'cmd'   :   '',
                    '_help' :   {
                                    'cmd'                       : _('List the systems the hosts run, with their reference host and how many packages they offer.'),
                                },
                },

    'available'    : {
                    '_cmd_usage_help' : _('Usage: otpme-inventory available [--host <host>] [--os-version <version>] [--arch <arch>] {package}'),
                    'cmd'   :   '--host :host: --os-version :os_version: --arch :arch: <package>',
                    '_help' :   {
                                    'cmd'                       : _('List the packages a system offers (e.g. openssl, "python3-*").'),
                                    '--host <host>'             : _('The system of this host, with the version installed there.'),
                                    '--os-version <version>'    : _('Only this OS version (e.g. debian-13).'),
                                    '--arch <arch>'             : _('Only this architecture (e.g. amd64).'),
                                },
                },
    }
