#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

""" OTPme main program. """

import os
import sys

# Add PYTHONPATH.
PYTHONPATH_FILE = "/etc/otpme/PYTHONPATH"
if os.path.exists(PYTHONPATH_FILE):
    fd = open(PYTHONPATH_FILE, "r")
    try:
        for x in fd.readlines():
            x = x.replace("\n", "")
            if x in sys.path:
                continue
            sys.path.insert(0, x)
    finally:
        fd.close()

import getpass
import setproctitle
# python3.
from importlib import reload

# Get tool name.
tool_name = str(os.path.basename(sys.argv[0]))

# Set proctitle.
current_proctitle = setproctitle.getproctitle()
if tool_name == "otpme-auth":
    new_proctitle = tool_name
else:
    new_proctitle = current_proctitle.split()
    new_proctitle = "%s %s" % (tool_name, " ".join(new_proctitle[2:]))
setproctitle.setproctitle(new_proctitle)

# Workaround for "ValueError: unsupported hash type md4" error on hashlib.new('md4')
import ctypes
try:
    ctypes.CDLL("libssl.so").OSSL_PROVIDER_load(None, b"legacy")
    ctypes.CDLL("libssl.so").OSSL_PROVIDER_load(None, b"default")
except (AttributeError, OSError):
    pass

## Workaround for https://github.com/pyca/cryptography/issues/7236
#from cryptography.hazmat.backends.openssl import backend
#backend._rsa_skip_check_key = True

def otpme_commands(no_debug=False):
    """ Handles OTPme command line tools. """
    from otpme.lib.classes.command_handler import CommandHandler
    command_handler = CommandHandler(interactive=True)

    ## Load extension schemas.
    #if config.use_api:
    #    from otpme.lib.extensions import utils
    #    utils.load_schemas()

    command_line = list(sys.argv)
    try:
        result = command_handler.handle_command(command,
                                command_line=command_line)
        exit_code = 0
    except OTPmeException as e:
        config.raise_exception()
        result = None
        exit_code = 1
        msg = str(e)
        if len(msg) > 0:
            if command != "auth" and subcommand != "verify":
                error_message(msg, newline=command_handler.newline)
    except Exception as e:
        raise

    if command == "auth":
        if subcommand == "verify":
            if exit_code == 0:
                if cache_seconds > 0:
                    try:
                        request_cacheable = result['request_cacheable']
                    except KeyError:
                        request_cacheable = False
                    if request_cacheable:
                        if cache == "redis":
                            redis_db.set(cache_key, nt_hash, ex=cache_seconds)
                        if cache == "memcached":
                            with pool.reserve() as mc:
                                mc.set(cache_key, nt_hash, time=cache_seconds)
                message("Accept")
            else:
                message("Reject")
        if subcommand == "verify_mschap":
            if exit_code == 0:
                try:
                    nt_key = result['nt_key']
                except KeyError:
                    message("ERR")
                else:
                    message("NT_KEY: "+nt_key)
            else:
                message("ERR")
        if not no_debug:
            if config.print_timing_results:
                from otpme.lib import debug
                debug.print_timing_result(print_status=True)
        # Using auth command with freeradius requires exit code 0
        # even on failed requests.
        return 0

    if result:
        message(result, newline=command_handler.newline)

    if not no_debug:
        if config.print_timing_results:
            from otpme.lib import debug
            debug.print_timing_result(print_status=True)

    return exit_code

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

# Get command from system command (e.g. otpme-user -> user).
command = "-".join(tool_name.split("-")[1:])

from otpme.lib.otpme_config import OTPmeConfig
config = OTPmeConfig(tool_name, auto_load=False)

#import trace
from otpme.lib.help import get_help
from otpme.lib.help import command_map
from otpme.lib.messages import message
from otpme.lib.help import get_main_opts
from otpme.lib.messages import error_message
from otpme.lib.help.register import register_help

from otpme.lib.exceptions import *

# Check if user requested our version.
if len(sys.argv) > 1 and sys.argv[1] == "--version":
    from otpme import __version__
    message(__version__)
    sys.exit(0)

# Remove command from argv.
sys.argv.pop(0)

help_needed = False
help_message = None
register_help()

# Set cli object type.
subcommand = None
object_type = "main"
if "--type" in sys.argv:
    opt_pos = sys.argv.index("--type")
    type_pos = opt_pos + 1
    try:
        object_type = sys.argv[type_pos]
        sys.argv.pop(type_pos)
        sys.argv.pop(opt_pos)
    except IndexError:
        help_message = "Missing object type: --type"
        help_msg = get_help(command, error=help_message)
        error_message(help_msg)
        sys.exit(0)
config.cli_object_type = object_type

# Check if we have to print the help screen.
try:
    get_main_opts(mod_name=object_type)
except OTPmeException as e:
    help_needed = True
    help_message = str(e)

try:
    need_command = command_map[command][object_type]['_need_command']
except:
    need_command = False
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
                        if i.startswith("-"):
                            continue
                        help_needed = False
        else:
            help_needed = True

if not help_needed:
    if tool_name == "otpme-auth":
        if subcommand == "verify":
            from otpme.lib import stuff
            from otpme.lib.cli import get_opts

            config_file = "/etc/otpme/otpme.conf"
            fd = open(config_file, "r")
            file_content = fd.read()
            fd.close()
            main_config = stuff.conf_to_dict(file_content)
            cache = main_config['CACHE']
            if cache == "redis":
                import redis
                from redis.connection import UnixDomainSocketConnection
                try:
                    redis_socket = main_config['REDIS_SOCKET']
                except:
                    redis_socket = "/var/run/otpme/sockets/redis.sock"
                pool = redis.ConnectionPool(path=redis_socket,
                            connection_class=UnixDomainSocketConnection)
                redis_db = redis.Redis(connection_pool=pool, db=0)

            if cache == "memcached":
                import pylibmc
                try:
                    memcache_socket = main_config['MEMCACHED_SOCKET']
                except:
                    memcache_socket = "/var/run/otpme/sockets/memcached.sock"
                mc = pylibmc.Client([memcache_socket])
                pool = pylibmc.ThreadMappedPool(mc)

            # Get command syntax.
            command_syntax = command_map[command]['main'][subcommand]['cmd']
            command_line = sys.argv[1:]
            object_cmd, \
            object_required, \
            object_list, \
            command_args = get_opts(command_syntax=command_syntax,
                                        command_line=command_line,
                                        command_args={})

            # Handle caching.
            try:
                cache_seconds = command_args['cache_seconds']
            except:
                cache_seconds = 0
            if cache_seconds > 0:
                client = command_args['client']
                try:
                    client_ip = command_args['client_ip']
                except:
                    client_ip = None
                if client or client_ip:
                    username = command_args['username']
                    password = command_args['password']
                    if client:
                        cache_key = "otpme-auth-cache-%s-%s" % (username, client)
                    else:
                        cache_key = "otpme-auth-cache-%s-%s" % (username, client_ip)
                    nt_hash = stuff.gen_nt_hash(str(password))
                    try:
                        if cache == "redis":
                            _nt_hash = redis_db.get(cache_key)
                        if cache == "memcached":
                            with pool.reserve() as mc:
                                _nt_hash = mc.get(cache_key)
                    except KeyError:
                        _nt_hash = None
                    if _nt_hash is not None:
                        if isinstance(_nt_hash, bytes):
                            _nt_hash = _nt_hash.decode()
                        if _nt_hash == nt_hash:
                            message("Accept")
                            sys.exit(0)

# Load OTPme config.
config.load(quiet=True)
# Print warning if API mode is requested and daemon is running.
if config.use_api:
    if not "--compgen" in sys.argv:
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

for x in sys.argv:
    if x != "--compgen":
        continue
    from otpme.lib.compgen import show_compgen
    show_compgen()
    sys.exit(0)

if help_needed:
    message(get_help(command, subcommand, error=help_message))
    sys.exit(1)

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
        stats.print_stats(10)
    else:
        exit_code = otpme_commands()

    sys.exit(exit_code)
