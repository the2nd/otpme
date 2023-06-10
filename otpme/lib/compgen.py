# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
# Distributed under the terms of the GNU General Public License v2
import os
import sys

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import help
#from otpme.lib import config
from otpme.lib.help import global_opts
from otpme.lib.help.register import register_help

register_help()

def show_compgen():
    """ Print valid compgen commands """
    cur = None
    counter = 0
    use_api = False
    comp_words = None
    #comp_cword = None
    for x in sys.argv:
        if x == "--api":
            use_api = True
            sys.argv.remove(x)
        if x == "--cur":
            cur = sys.argv[counter+1]
            sys.argv.remove(x)
        if x == "--comp-cword":
            #comp_cword = int(sys.argv[counter+1])
            sys.argv.remove(x)
        if x == "--comp-words":
            comp_words = sys.argv[counter+1].split()
            sys.argv.remove(x)
        counter += 1

    tool_name = comp_words[0]
    main_command  = tool_name.split("-")[1]

    # Check for stdout redirection.
    prev_opt_pos = len(comp_words) - 1
    if comp_words[-1] == cur:
        prev_opt_pos -= 1
    prev_opt = comp_words[prev_opt_pos]
    if prev_opt == ">":
        return

    _global_opts = []
    for x in global_opts:
        for y in x:
            if not y.startswith("-"):
                continue
            x_opt = y.split()[0]
            _global_opts.append(x_opt)

    help_dict = help.get_cmd_help(main_command)

    sub_command = None
    need_objects = False
    object_type = main_command
    for word in comp_words[1:]:
        if word.startswith("-"):
            continue
        if word != cur:
            sub_command = word
            break

    if sub_command == "add":
        if main_command == "token":
            need_objects = True
            object_type = "user"

    if sub_command is None:
        if cur.startswith("-"):
            print(" ".join(_global_opts))
        else:
            sub_commands = list(help_dict)
            for x_command in list(sub_commands):
                try:
                    help_dict[x_command]['_cmd_usage_help']
                except:
                    sub_commands.remove(x_command)
            sub_commands = " ".join(sub_commands)
            print(sub_commands)

    elif sub_command and cur.startswith("-"):
        try:
            cmd_help = help_dict[sub_command]['cmd']
            cmd_help = cmd_help.split()
        except KeyError:
            cmd_help = []
        for x in cmd_help:
            if not x.startswith("-"):
                continue
            print(x)

    else:
        prev_opt_pos = len(comp_words) - 1
        if comp_words[-1] == cur:
            prev_opt_pos -= 1
        prev_opt = comp_words[prev_opt_pos]
        if prev_opt.startswith("-"):
            cmd_help = help_dict[sub_command]['cmd']
            cmd_help = cmd_help.split()
            counter = 0
            for x in cmd_help:
                counter += 1
                if x != prev_opt:
                    continue
                x_para = cmd_help[counter]
                if x_para.startswith(":") and x_para.endswith(":"):
                    if "=" not in x_para:
                        need_objects = False
                        x_type = x_para.split(":")[1]
                        # Check if parameter need an object
                        x_help = help.get_cmd_help(x_type)
                        if x_help:
                            need_objects = True
                            object_type = x_type
                break

        # Load OTPme config.
        from otpme.lib.otpme_config import OTPmeConfig
        config = OTPmeConfig(tool_name, quiet=True)
        config.use_api = use_api
        from otpme.lib.register import register_modules
        register_modules()
        if object_type in config.tree_object_types:
            need_objects = True

        if need_objects:
            from otpme.lib.classes.command_handler import CommandHandler
            command_handler = CommandHandler()
            cmd_line = ["list"]
            if cur:
                cmd_line.append("%s*" % cur)
            objects = command_handler.handle_command(command=object_type,
                                                    command_line=cmd_line)
            print(objects)

