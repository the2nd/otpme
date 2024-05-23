# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import re
import sys
from prettytable import PrettyTable

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib.exceptions import *

global_opts = []

command_map = {
    # ::        = required opt
    # :         = optional opt
    # :[name]:  = opt is a list (e.g. val1,val2,val3,...)
    # :{name}:  = opt is a dict (e.g. arg1=val1,arg2=val2,...)
    # <>        = required para
    # []        = optional para
    # |object|  = OTPme object
    }

debug_opts_mapping = {
                'a'         : 'func_cache_adds',
                'A'         : 'transactions',
                'b'         : 'backend_reads',
                'c'         : 'object_caching',
                'r'         : 'file_reads',
                'w'         : 'file_writes',
                'C'         : 'client',
                'd'         : 'base',
                'D'         : 'daemonize',
                'e'         : 'raise_exceptions',
                'h'         : 'func_cache_hits',
                'L'         : 'locking',
                'm'         : 'module_loading',
                'M'         : 'method_calls',
                'N'         : 'net_traffic',
                't'         : 'debug_timestamps',
                'T'         : 'debug_timings',
                'P'         : 'debug_profile',
            }

def register_cmd_help(command, help_dict, mod_name=None):
    global command_map
    if command not in command_map:
        command_map[command] = {}
    if mod_name is None:
        mod_name = "main"
    for x in help_dict:
        if mod_name not in command_map[command]:
            command_map[command][mod_name] = {}
        command_map[command][mod_name][x] = help_dict[x]

def register_global_opt(opt, help_text):
    global global_opts
    global_opts.append((opt, help_text))

def get_cmd_help(command, mod_name=None):
    from otpme.lib import config
    global command_map
    if mod_name is None:
        mod_name = config.cli_object_type
    try:
        help_dict = command_map[command][mod_name]
    except:
        help_dict = {}
    return help_dict

# FIXME: we need to import global opts from a version dependent location!!
register_global_opt("-r <realm>", "Connect to realm")
register_global_opt("-s <site>", "Connect to site")
register_global_opt("-u <user>", "Connect as user")
register_global_opt("--type <object_type>", "Object type to act on (e.g. token type).")
register_global_opt("-t <timeout>", "Connect timeout in seconds")
register_global_opt("-tt <timeout>", "Connection timeout in seconds")
register_global_opt("-c <config_file>", "Use alternative config file")
register_global_opt("-f", "Do not ask any user questions")
register_global_opt("--no-dns", "Do not resolve OTPme site address via DNS")
register_global_opt("--use-dns", "Resolve OTPme site address via DNS")
register_global_opt("--login-no-dns", "Do not resolve OTPme login point via DNS")
register_global_opt("--login-use-dns", "Resolve OTPme login point via DNS")
register_global_opt("--no-auth", "Do not ask for credentials if not logged in")
register_global_opt("--use-agent [y|n|auto]", "Use otpme-agent login session to connect to daemons")
register_global_opt("--use-ssh-agent [y|n]", "Use ssh-agent for authentication")
register_global_opt("--use-smartcard [y|n]", "Use smartcard for authentication")
register_global_opt("--stdin-pass", "Read passphrase from stdin")
register_global_opt("--api", "Use direct API calls instead of connecting to a daemon")
register_global_opt("--auth-token [token]", "Emulate login with [token] in API mode")
register_global_opt("--print-raw-sign-data", "Print raw data to sign instead of sign info")
#register_global_opt("--ignore-changed-objects", "Sync objects even if they changed while syncing.")
register_global_opt("--version", "Show version")
register_global_opt("-v", "Enable verbose mode")
register_global_opt("-d", "Enable debug mode. Multiple 'd' will increase debug level")
register_global_opt("-da", "Debug function cache adds")
register_global_opt("-dA", "Enable debug of transactions.")
register_global_opt("-db", "Print when objects are read from backend")
register_global_opt("-dc", "Print when objects are read from cache")
register_global_opt("-dr", "Print file reads")
register_global_opt("-dw", "Print file writes")
register_global_opt("-dC", "Enable debug logging for client messages")
register_global_opt("-dD", "Do not go to background and log to stdout.")
register_global_opt("-de", "Print tracebacks.")
register_global_opt("-dee", "Raise debug exceptions.")
register_global_opt("-dh", "Debug function cache hits.")
register_global_opt("-dL", "Debug locks.")
register_global_opt("-dm", "Print loading of OTPme modules")
register_global_opt("-dM", "Enable function/method call tracing")
register_global_opt("-dN", "Debug network packets.")
register_global_opt("-dt", "Enable timestamps in debug output")
register_global_opt("-dP", "Enable profiling via cProfile")
register_global_opt("-dT", "Print warning if timing of function/method calls takes longer than --debug-timing-limit.")
register_global_opt("-dTT", "Print timing result after method finishes.")
register_global_opt("-dTTT", "Print warning each time method call gets slower.")
register_global_opt("--color-logs", "Use colored logs.")
register_global_opt("--log-filter <syncd,authd>", "Only print log messages for the given daemons.")
register_global_opt("--lock-timeout <int>", "Lock timeout in seconds when starting jobs.")
register_global_opt("--lock-wait-timeout <int>", "Lock wait timeout in seconds when starting jobs.")
register_global_opt("--lock-ignore-changed-objects", "Ignore if an object changed while waiting for lock.")
register_global_opt("--job-timeout <int>", "Job timeout.")
register_global_opt("--disable-locking", "Disable locking in API mode (use with caution!).")
register_global_opt("--disable-transactions", "Disable transactions.")
register_global_opt("--debug-daemons <authd,mgmtd>", "Enable debug stuff only for the given daemons.")
register_global_opt("--debug-profile-sort <cumtime,ncalls,tottime,percall>", "Statistic output sorting.")
register_global_opt("--debug-func-caches <instance_cache,search_cache>", "Enable debug stuff only for the given function caches.")
register_global_opt("--debug-func-names <method1,method2>", "Enable timing for given functions only.")
register_global_opt("--debug-func-start <method1,method2>", "Start timing on method call.")
register_global_opt("--debug-users <user1,user2>", "Enable debug stuff only for the given users.")
register_global_opt("--debug-timing-limit <seconds>", "Print warning if function/method call takes longer than <seconds>.")
register_global_opt("--debug-counter-limit <call_count>", "Print warning if function/method is called more than <call_count>.")

# FIXME: One reason why get_help() is located in help.py is
#        the import time compared to putting it into e.g. cli.py.
#        Showing help should be as fast as possible because its
#        used for bash completion stuff.
def get_help(command, subcommand=None, command_map=None,
    error=None, mod_name=None, include_main_usage_help=True):
    """ Show command help. """
    #from otpme.lib import debug
    #x = debug.trace()
    #import json
    #x = json.dumps(x)
    #fd = open("/tmp/log", "w")
    #fd.write(x)
    #fd.close()
    from otpme.lib import config
    # Get default command map if none was given
    if not command_map:
        from otpme.lib.help import command_map

    if mod_name is None:
        mod_name = config.cli_object_type
    if mod_name is None:
        mod_name = "main"

    if subcommand:
        try:
            return command_map[command][mod_name][subcommand]['_cmd_usage_help']
        except:
            subcommand = None

    main_usage_help = ""

    cmd_table = []
    opt_table = []

    if not command in command_map:
        raise OTPmeException("Command not in command map: %s" % command)

    # Get main command help
    try:
        main_command_help = command_map[command][mod_name]['_help']
    except:
        main_command_help = None

    command_count = 0
    for c in sorted(command_map[command][mod_name]):
        opt_count = 0
        if c == "_need_command":
            continue
        if c == "_include_main_opts":
            continue
        if c == "_include_global_opts":
            continue
        if c == "_usage_help":
            main_usage_help = command_map[command][mod_name][c]
            continue
        if not '_help' in command_map[command][mod_name][c]:
            continue
        for f in command_map[command][mod_name][c]['_help']:
            if f == "cmd":
                help_text = "\t- %s" % command_map[command][mod_name][c]['_help'][f]
                row = [ " %s" % c, help_text ]
                cmd_table.append(row)
            else:
                if opt_count == 0:
                    if command_count != 0:
                        row = [ "", "" ]
                        opt_table.append(row)
                    row = [ " %s:" % c, "" ]
                    opt_table.append(row)
                help_text = "\t- %s" % command_map[command][mod_name][c]['_help'][f]
                row = [ "   %s" % f, help_text ]
                opt_table.append(row)
                opt_count += 1
            command_count += 1

    try:
        include_main_opts = command_map[command][mod_name]['_include_main_opts']
    except:
        include_main_opts = False

    main_command_opts = None
    if include_main_opts:
        main_command_opts = get_help(command=command,
                                    subcommand=subcommand,
                                    mod_name="main",
                                    include_main_usage_help=False)

    try:
        include_global_opts = command_map[command][mod_name]['_include_global_opts']
    except:
        include_global_opts = False

    glob_opt_table = []
    if include_global_opts:
        glob_opt_table.append([ '', '' ])
        glob_opt_table.append([ ' global:', '' ])
        for x in global_opts:
            help_text = "\t- %s" % x[1]
            row = [ "   %s" % x[0], help_text ]
            glob_opt_table.append(row)

    # Add main command options help
    if len(opt_table) > 0 or include_global_opts or (main_command_help and len(main_command_help) > 0):
        if main_command_help:
            for opt in sorted(main_command_help):
                if opt == "cmd":
                    continue
                help_text = main_command_help[opt]
                row = [ "   %s" % opt, help_text ]
                opt_table.insert(0, row)
            row = [ "", "" ]
            opt_table.insert(0, row)
        row = [ "Options:", "" ]
        opt_table.insert(0, row)
        row = [ "", "" ]
        opt_table.insert(0, row)

    table_headers = [ "command", "help" ]
    table = PrettyTable(table_headers, header_style="title")
    table.align = "l"
    table.padding_width = 0
    table.right_padding_width = 1

    opts_list = cmd_table + opt_table + glob_opt_table
    for i in opts_list:
        table.add_row(i)

    # Get output string from table.
    output = table.get_string(header=False, border=False)

    message = []
    if include_main_usage_help and main_usage_help:
        message.append(main_usage_help)
    if output:
        message.append("")
        message.append("Commands:")
        message.append(output)
    if main_command_opts:
        message.append(main_command_opts)
    if error is not None:
        message.append("")
        message.append(error)

    return "\n".join(message)

main_opts = {}

def get_main_opts(clear_cache=False, mod_name=None):
    """ Get main options from sys.argv. """
    from otpme.lib import config
    # We need global var to cache main opts. This is required because we call
    # this function before we import the config module in otpme.py. We do this
    # for performance reasons because our bash-completion stuff often calls
    # the otpme-* command with just -h.
    global main_opts

    if mod_name is None:
        mod_name = config.cli_object_type

    if clear_cache:
        main_opts = {}

    if main_opts:
        return main_opts
    # Check if we can access argv (e.g. main otpme.py where not called from
    # freeradius as a module).
    try:
        sys.argv[0]
    except:
        # By default we dont print tracebacks.
        main_opts['print_tracebacks'] = False
        return main_opts

    if len(sys.argv) == 0:
        return main_opts

    if len(sys.argv) == 0:
        return main_opts

    def set_debug_level(slot="base"):
        global main_opts
        try:
            debug_levels = main_opts['debug_levels']
        except:
            debug_levels = {}
        try:
            x_debug_level = debug_levels[slot]
        except:
            x_debug_level = 0
        x_debug_level += 1
        debug_levels[slot] = x_debug_level
        main_opts['debug_levels'] = debug_levels
        if slot == "base":
            main_opts['verbose_level'] = 10
            main_opts['debug_enabled'] = True
        if slot == "daemonize":
            main_opts['daemonize'] = False
        if slot == "file_reads":
            os.environ['OTPME_DEBUG_FILE_READ'] = "True"
        if slot == "file_writes":
            os.environ['OTPME_DEBUG_FILE_WRITE'] = "True"
        if slot == "module_loading":
            os.environ['OTPME_DEBUG_MODULE_LOADING'] = "True"
        if slot == "raise_exceptions":
            main_opts['print_tracebacks'] = True
            if x_debug_level > 1:
                main_opts['raise_exceptions'] = True

    def parse_debug_opts(opts):
        """ Parse debug options + level. """
        counter = 0
        cur_opt = None
        opts_len = len(opts)
        lett_re = re.compile('^[a-zA-Z]$')
        numb_re = re.compile('^[0-9]$')
        for x in reversed(opts):
            is_letter = False
            is_number = False
            if lett_re.match(x):
                is_letter = True
            elif numb_re.match(x):
                is_number = True
            else:
                msg = "Invalid option: %s" % x
                raise OTPmeException(msg)

            counter += 1

            if cur_opt is None:
                cur_opt = x
                if is_letter:
                    cur_type = "letter"
                if is_number:
                    cur_type = "number"
                if opts_len == counter:
                    if is_letter:
                        for c in cur_opt:
                            try:
                                debug_opt = debug_opts_mapping[c]
                            except:
                                msg = "Invalid option: %s" % c
                                raise OTPmeException(msg)
                            set_debug_level(debug_opt)
                continue

            if cur_type == "letter":
                if is_letter:
                    if x in cur_opt:
                        cur_opt = "%s%s" % (x, cur_opt)
                    else:
                        for c in cur_opt:
                            try:
                                debug_opt = debug_opts_mapping[c]
                            except:
                                msg = "Invalid option: %s" % c
                                raise OTPmeException(msg)
                            set_debug_level(debug_opt)
                        cur_opt = x

                if is_number:
                    for c in cur_opt:
                        try:
                            debug_opt = debug_opts_mapping[c]
                        except:
                            msg = "Invalid option: %s" % c
                            raise OTPmeException(msg)
                        set_debug_level(debug_opt)
                    cur_opt = x
                    cur_type = "number"
                    continue

            elif cur_type == "number":
                if is_letter:
                    cur_opt = "%s%s" % (x, cur_opt)
                    try:
                        debug_opt = debug_opts_mapping[cur_opt]
                    except:
                        msg = "Invalid option: %s" % cur_opt
                        raise OTPmeException(msg)
                    set_debug_level(debug_opt)
                    cur_opt = None
                    cur_type = None
                    continue

                if is_number:
                    cur_opt = "%s%s" % (x, cur_opt)

            if opts_len == counter:
                if is_letter:
                    for c in cur_opt:
                        try:
                            debug_opt = debug_opts_mapping[c]
                        except:
                            msg = "Invalid option: %s" % c
                            raise OTPmeException(msg)
                        set_debug_level(debug_opt)

    verbose_re = re.compile('^-[v]*$')
    # set variable depending on command line arguments
    for x in list(sys.argv):
        if len(sys.argv) == 0:
            break
        if sys.argv[0].startswith("-d"):
            sub_opts = sys.argv[0][2:]
            if len(sub_opts) == 0:
                raise OTPmeException("Incomplete option: -d")
            parse_debug_opts(sub_opts)
            sys.argv.pop(0)
        elif verbose_re.match(sys.argv[0]):
            verbose_level = 0
            for i in sys.argv[0]:
                if i == "v":
                    verbose_level += 1
            main_opts['verbose_level'] = verbose_level
            sys.argv.pop(0)
        elif sys.argv[0] == "--print-raw-sign-data":
            main_opts['print_raw_sign_data'] = True
            sys.argv.pop(0)
        elif sys.argv[0] == "--no-sync-mem-cache":
            main_opts['sync_mem_cache'] = False
            sys.argv.pop(0)
        elif sys.argv[0] == "--ignore-changed-objects":
            main_opts['hostd_sync_ignore_changed_objects'] = True
            sys.argv.pop(0)
        elif sys.argv[0] == "--color-logs":
            main_opts['color_logs'] = True
            sys.argv.pop(0)
        elif sys.argv[0] == "--no-dns":
            main_opts['use_dns'] = False
            sys.argv.pop(0)
        elif sys.argv[0] == "--use-dns":
            main_opts['use_dns'] = True
            sys.argv.pop(0)
        elif sys.argv[0] == "--login-no-dns":
            main_opts['login_use_dns'] = False
            sys.argv.pop(0)
        elif sys.argv[0] == "--login-use-dns":
            main_opts['login_use_dns'] = True
            sys.argv.pop(0)
        elif sys.argv[0] == "--no-auth":
            main_opts['no_auth'] = True
            sys.argv.pop(0)
        elif sys.argv[0] == "--api":
            main_opts['use_api'] = True
            sys.argv.pop(0)
        elif sys.argv[0] == "--auth-token":
            sys.argv.pop(0)
            api_auth_token = str(sys.argv[0])
            sys.argv.pop(0)
            main_opts['api_auth_token'] = api_auth_token
        elif sys.argv[0] == "--use-ssh-agent":
            sys.argv.pop(0)
            a = sys.argv[0]
            sys.argv.pop(0)
            if a == "y":
                main_opts['use_ssh_agent'] = True
            elif a == "n":
                main_opts['use_ssh_agent'] = False
        elif sys.argv[0] == "--use-smartcard":
            sys.argv.pop(0)
            a = sys.argv[0]
            sys.argv.pop(0)
            if a == "y":
                main_opts['use_smartcard'] = True
            elif a == "n":
                main_opts['use_smartcard'] = False
        elif sys.argv[0] == "--use-agent":
            sys.argv.pop(0)
            a = sys.argv[0]
            sys.argv.pop(0)
            if a == "y":
                main_opts['use_agent'] = True
            elif a == "n":
                main_opts['use_agent'] = False
            else:
                main_opts['use_agent'] = a
        elif sys.argv[0] == "--keep-floating-ip":
            sys.argv.pop(0)
            main_opts['keep_floating_ip'] = True
        elif sys.argv[0] == "--stdin-pass":
            sys.argv.pop(0)
            main_opts['read_stdin_pass'] = True
        elif sys.argv[0] == "-f":
            main_opts['force'] = True
            sys.argv.pop(0)
        elif sys.argv[0] == "-l":
            main_opts['file_logging'] = True
            sys.argv.pop(0)
            main_opts['force_logfile'] = str(sys.argv[0])
            sys.argv.pop(0)
        elif sys.argv[0] == "-t":
            sys.argv.pop(0)
            try:
                connect_timeout = int(sys.argv[0])
            except:
                raise OTPmeException("-t requires seconds as integer")
            main_opts['connect_timeout'] = connect_timeout
            sys.argv.pop(0)
        elif sys.argv[0] == "-tt":
            sys.argv.pop(0)
            try:
                connection_timeout = int(sys.argv[0])
            except:
                raise OTPmeException("-tt requires seconds as integer")
            main_opts['connection_timeout'] = connection_timeout
            sys.argv.pop(0)
        elif sys.argv[0] == "--reneg-timeout":
            sys.argv.pop(0)
            try:
                reneg_timeout = int(sys.argv[0])
            except:
                raise OTPmeException("--reneg-timeout requires seconds as integer")
            main_opts['reneg_timeout'] = reneg_timeout
            sys.argv.pop(0)
        elif sys.argv[0] == "--log-filter":
            sys.argv.pop(0)
            try:
                log_filter = sys.argv[0].split(",")
            except:
                raise OTPmeException("--log-filter requires a comma separated list")
            main_opts['log_filter'] = log_filter
            sys.argv.pop(0)
        elif sys.argv[0] == "--cache-flush":
            sys.argv.pop(0)
            main_opts['flush_cache_on_start'] = True
        elif sys.argv[0] == "--no-cache-start":
            sys.argv.pop(0)
            main_opts['autostart_cache'] = False
        elif sys.argv[0] == "--no-index-start":
            sys.argv.pop(0)
            main_opts['autostart_index'] = False
        elif sys.argv[0] == "--debug-daemons":
            sys.argv.pop(0)
            try:
                debug_daemons = sys.argv[0].split(",")
            except:
                raise OTPmeException("--debug-daemons requires a comma separated list")
            main_opts['debug_daemons'] = debug_daemons
            sys.argv.pop(0)
        elif sys.argv[0] == "--debug-users":
            sys.argv.pop(0)
            try:
                debug_users = sys.argv[0].split(",")
            except:
                raise OTPmeException("--debug-users requires a comma separated list")
            main_opts['debug_users'] = debug_users
            sys.argv.pop(0)
        elif sys.argv[0] == "--debug-profile-sort":
            sys.argv.pop(0)
            main_opts['debug_profile_sort'] = str(sys.argv[0])
            sys.argv.pop(0)
        elif sys.argv[0] == "--debug-func-start":
            sys.argv.pop(0)
            try:
                debug_func_start = sys.argv[0].split(",")
            except:
                raise OTPmeException("--debug-func-start requires a comma separated list")
            main_opts['debug_func_start'] = debug_func_start
            sys.argv.pop(0)
        elif sys.argv[0] == "--debug-func-names":
            sys.argv.pop(0)
            try:
                debug_func_names = sys.argv[0].split(",")
            except:
                raise OTPmeException("--debug-func-names requires a comma separated list")
            main_opts['debug_func_names'] = debug_func_names
            sys.argv.pop(0)
        elif sys.argv[0] == "--debug-func-caches":
            sys.argv.pop(0)
            try:
                debug_func_caches = sys.argv[0].split(",")
            except:
                raise OTPmeException("--debug-func-caches requires a comma separated list")
            main_opts['debug_func_caches'] = debug_func_caches
            sys.argv.pop(0)
        elif sys.argv[0] == "--debug-timing-limit":
            sys.argv.pop(0)
            try:
                debug_timing_limit = float(sys.argv[0])
            except:
                raise OTPmeException("--debug-timing-limit requires a int/float")
            main_opts['debug_timing_limit'] = debug_timing_limit
            sys.argv.pop(0)
        elif sys.argv[0] == "--debug-counter-limit":
            sys.argv.pop(0)
            try:
                debug_counter_limit = int(sys.argv[0])
            except:
                raise OTPmeException("--debug-counter-limit requires a int")
            main_opts['debug_counter_limit'] = debug_counter_limit
            sys.argv.pop(0)
        elif sys.argv[0] == "--lock-timeout":
            sys.argv.pop(0)
            try:
                main_opts['lock_timeout'] = int(sys.argv.pop(0))
            except:
                msg = ("--lock-timeout requires an int")
                raise OTPmeException(msg)
        elif sys.argv[0] == "--lock-wait-timeout":
            sys.argv.pop(0)
            try:
                main_opts['lock_wait_timeout'] = int(sys.argv.pop(0))
            except:
                msg = ("--lock-wait-timeout requires an int")
                raise OTPmeException(msg)
        elif sys.argv[0] == "--lock-ignore-changed-objects":
            sys.argv.pop(0)
            main_opts['ignore_changed_objects'] = True
        elif sys.argv[0] == "--job-timeout":
            sys.argv.pop(0)
            main_opts['job_timeout'] = int(sys.argv[0])
            sys.argv.pop(0)
        elif sys.argv[0] == "--disable-locking":
            sys.argv.pop(0)
            main_opts['locking_enabled'] = False
        elif sys.argv[0] == "--disable-transactions":
            sys.argv.pop(0)
            main_opts['transactions_enabled'] = False
        elif sys.argv[0] == "-u":
            sys.argv.pop(0)
            main_opts['login_user'] = str(sys.argv[0])
            sys.argv.pop(0)
        elif sys.argv[0] == "-r":
            sys.argv.pop(0)
            main_opts['connect_realm'] = str(sys.argv[0])
            sys.argv.pop(0)
        elif sys.argv[0] == "-s":
            sys.argv.pop(0)
            main_opts['connect_site'] = str(sys.argv[0])
            sys.argv.pop(0)
        elif sys.argv[0] == "-c":
            sys.argv.pop(0)
            main_opts['config_file'] = str(sys.argv[0])
            sys.argv.pop(0)

    return main_opts
