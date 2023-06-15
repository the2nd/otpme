#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

""" OTPme main program. """

import os
import sys
import getpass
import setproctitle
# python3.
from importlib import reload

# We need this to get gettext module working with e.g. umlauts.
if sys.version[0] == '2':
    reload(sys)
    sys.setdefaultencoding('utf8')
    #print(sys.getdefaultencoding())

# Workaround used for OTPme development.
if __name__ == "__main__":
    my_path = os.path.realpath(sys.argv[0])
    my_path = os.path.dirname(my_path)
    my_path = os.path.dirname(my_path)
    sys.path.append(my_path)

# Add PYTHONPATH.
PYTHONPATH_FILE = "/etc/otpme/PYTHONPATH"
if os.path.exists(PYTHONPATH_FILE):
    fd = open(PYTHONPATH_FILE, "r")
    try:
        for x in fd.readlines():
            x = x.replace("\n", "")
            if x in sys.path:
                continue
            sys.path.append(x)
    finally:
        fd.close()

#import trace
from otpme.lib.help import get_help
from otpme.lib.help import command_map
from otpme.lib.messages import message
from otpme.lib.help import get_main_opts
from otpme.lib.messages import error_message

from otpme.lib.exceptions import *

# Get tool name.
tool_name = str(os.path.basename(sys.argv[0]))
# Get command from system command (e.g. otpme-user -> user).
command = "-".join(tool_name.split("-")[1:])

# Set proctitle.
current_proctitle = setproctitle.getproctitle()
new_proctitle = current_proctitle.split()
new_proctitle = "%s %s" % (tool_name, " ".join(new_proctitle[2:]))
setproctitle.setproctitle(new_proctitle)

#setproctitle.setproctitle(tool_name)
sys.argv.pop(0)

# Load OTPme config.
from otpme.lib.otpme_config import OTPmeConfig
config = OTPmeConfig(tool_name, quiet=True)

# Register help.
from otpme.lib.help.register import register_help
register_help()

help_needed = False
help_message = None

# Set cli object type.
subcommand = None
object_type = "main"
if "--type" in sys.argv:
    opt_pos = sys.argv.index("--type")
    type_pos = opt_pos + 1
    try:
        object_type = sys.argv[type_pos]
        sys.argv.pop(opt_pos)
        sys.argv.pop(opt_pos)
    except IndexError:
        help_message = "Missing object type: --type"
        help_msg = get_help(command, error=help_message)
        error_message(help_msg)
        sys.exit(0)
config.cli_object_type = object_type

for x in sys.argv:
    if x != "--compgen":
        continue
    from otpme.lib.compgen import show_compgen
    show_compgen()
    sys.exit(0)

# Only root can control OTPme daemons.
if command == "controld":
    # Get system user.
    system_user = getpass.getuser()
    if system_user != "root":
        error_message("Permission denied.")
        sys.exit(1)
    # Change dir to otpme base directory on daemon start.
    if os.path.exists(config.base_dir):
        os.chdir(config.base_dir)

# Check if user requested our version.
if len(sys.argv) > 1 and sys.argv[1] == "--version":
    message(config.my_name + "_" + config.my_version)
    sys.exit(0)

# Check if we have to print the help screen.
try:
    get_main_opts()
except OTPmeException as e:
    help_needed = True
    help_message = str(e)

need_command = command_map[command][object_type]['_need_command']
if need_command:
    if len(sys.argv) == 0:
        help_needed = True
    else:
        subcommand = sys.argv[0]
        if subcommand in command_map[command][object_type]:
            command_min_args = 0
            try:
                cmd_line = command_map[command][object_type][subcommand]['cmd'].split(" ")
            except:
                cmd_line = []
            for x in cmd_line:
                if x.startswith("<") and x.endswith(">"):
                    command_min_args += 1
            if len(sys.argv) < (command_min_args + 1) \
            or (len(sys.argv) > 1 and sys.argv[1] == "-h"):
                help_needed = True

            if command_min_args > 0:
                if not help_needed:
                    help_needed = True
                    for i in sys.argv[0:]:
                        if not i.startswith("-"):
                            help_needed = False
        else:
            help_needed = True
if help_needed:
    message(get_help(command, subcommand, error=help_message))
    sys.exit(1)

# Print warning if API mode is requested and daemon is running.
if config.use_api:
    if os.path.exists(config.controld_pidfile):
        error_message("Warning!!! API mode should be used with care while "
        + "daemons are running. Your changes may be lost or result in "
        + "malfunction!")

# Check if all required modules are installed.
config.check_modules()

# Verify OTPme config.
try:
    config.verify()
except Exception as e:
    raise Exception("OTPme config verification failed: " + str(e))

## Import freeradius stuff if we got called as a module.
#if __name__ == 'otpme':
#    from otpme.lib import init
#    from otpme.lib.freeradius.otpme import instantiate
#    from otpme.lib.freeradius.otpme import authenticate
#    from otpme.lib.freeradius.otpme import authorize
#    from otpme.lib.freeradius.otpme import detach
#
#elif __name__ == '__main__':

def otpme_commands():
    """ Handles OTPme command line tools. """
    from otpme.lib.classes.command_handler import CommandHandler
    command_handler = CommandHandler()

    ## Load extension schemas.
    #if config.use_api:
    #    from otpme.lib.extensions import utils
    #    utils.load_schemas()

    try:
        result = command_handler.handle_command(command,
                                command_line=list(sys.argv))
        exit_code = 0
    except OTPmeException as e:
        result = None
        exit_code = 1
        config.raise_exception()
        msg = str(e)
        if len(msg) > 0:
            error_message(msg, newline=command_handler.newline)
    except Exception as e:
        raise

    if result:
        message(result, newline=command_handler.newline)

    if config.print_timing_results:
        from otpme.lib import debug
        debug.print_timing_result(print_status=True)

    return exit_code

# Workaround used for OTPme development.
if __name__ == "__main__":
    if config.debug_level("debug_profile") > 0:
        import pstats
        import cProfile
        profiler = cProfile.Profile()
        profiler.enable()
        exit_code = otpme_commands()
        profiler.disable()
        sort_by = config.debug_profile_sort
        stats = pstats.Stats(profiler).sort_stats(sort_by)
        #stats = pstats.Stats(profiler).sort_stats('ncalls')
        #stats = pstats.Stats(profiler).sort_stats('tottime')
        #stats = pstats.Stats(profiler).sort_stats('percall')
        #stats = pstats.Stats(profiler).sort_stats('cumtime')
        stats.print_stats()
    else:
        exit_code = otpme_commands()
    sys.exit(exit_code)
