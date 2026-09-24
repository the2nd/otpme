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
    '_usage_help'               : _("Usage: otpme-inventory {command} [host]"),

    'show'    : {
                    '_cmd_usage_help' : _('Usage: otpme-inventory show {host}'),
                    'cmd'   :   '<host>',
                    '_help' :   {
                                    'cmd'                       : _('Show the system of a host and how many packages it has.'),
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
                    '_cmd_usage_help' : _('Usage: otpme-inventory search [--host <host>] [--os-version <version>] [--hardware <expression>] [package]'),
                    'cmd'   :   '--host :host: --os-version :os_version: --hardware :hardware: [package]',
                    '_help' :   {
                                    'cmd'                       : _('Search hosts by package (e.g. openssl, "openssl=3.0.*"), OS version or hardware.'),
                                    '--host <host>'             : _('Only this host (e.g. to search its packages).'),
                                    '--os-version <version>'    : _('Only hosts with this OS version (e.g. debian-12).'),
                                    '--hardware <expression>'   : _('Only hosts whose hardware matches (e.g. serial=ABC123, "memory<8G").'),
                                },
                },
    }
