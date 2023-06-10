# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
# Distributed under the terms of the GNU General Public License v2
import os
import sys
import glob

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
    from otpme.lib import config
    cur = None
    counter = 0
    comp_words = None
    #comp_cword = None
    for x in sys.argv:
        if x == "--cur":
            try:
                cur = sys.argv[counter+1]
            except IndexError:
                cur = ""
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
    prev_word_pos = len(comp_words) - 1
    if comp_words[-1] == cur:
        prev_word_pos -= 1
    prev_word = comp_words[prev_word_pos]
    if prev_word == ">":
        return

    sub_command = None
    need_objects = False
    object_type = main_command

    # Get previous word.
    prev_word_pos = len(comp_words) - 1
    if comp_words[-1] == cur:
        prev_word_pos -= 1
    prev_word = comp_words[prev_word_pos]

    # Get command help.
    help_dict = help.get_cmd_help(main_command)

    # Check if command line already includes a subcommand.
    word_counter = 0
    found_subcommand = False
    sub_commands = list(help_dict)
    comp_words_rev = list(reversed(comp_words))
    for word in comp_words_rev:
        if word not in sub_commands:
            word_counter += 1
            continue
        prev_subcommand_word = comp_words_rev[word_counter+1]
        #print(reversed(comp_words_rev))
        #print(word_counter)
        #print(prev_subcommand_word)
        # Parameter to the --type option may conflict with subcommands.
        if prev_subcommand_word == "--type":
            break
        if cur == word:
            break
        sub_command = word
        found_subcommand = True
        word_counter += 1

    print("fou", found_subcommand)
    # Check for global options.
    global_opts_done = True
    if not found_subcommand:
        for x in global_opts:
            check_global_opts = False
            check_global_opts_paras = False
            x_opt = x[0].split()[0]
            if cur.startswith("-"):
                check_opt = cur
                check_global_opts = True
            elif prev_word.startswith("-"):
                check_opt = prev_word
                check_global_opts = True
                check_global_opts_paras = True

            if check_global_opts:
                if check_opt not in x_opt:
                    continue
                if check_global_opts_paras:
                    try:
                        x_para = x[0].split()[1]
                    except IndexError:
                        x_para = None
                    if prev_word == x_opt:
                        if x_para:
                            if x_opt == "--type":
                                if main_command == "token":
                                    glob_str = "%s/*/[!_]*.py" % config.token_dir
                                    token_files = glob.glob(glob_str)
                                    for x in token_files:
                                        token_type = os.path.basename(x)
                                        token_type = token_type.replace(".py", "")
                                        print(token_type)
                                    return
                                if main_command == "policy":
                                    glob_str = "%s/*/[!_]*.py" % config.policy_dir
                                    policy_files = glob.glob(glob_str)
                                    for x in policy_files:
                                        policy_type = os.path.basename(x)
                                        policy_type = policy_type.replace(".py", "")
                                        print(policy_type)
                                    return
                            global_opts_done = False
                else:
                    print(x_opt)
                    global_opts_done = False

    if not global_opts_done:
        return

    # Token add command requires a user.
    if main_command == "token":
        if sub_command == "add":
            need_objects = True
            object_type = "user"

    if sub_command is None:
        # List all subcommands
        sub_commands = list(help_dict)
        for x_command in list(sub_commands):
            try:
                help_dict[x_command]['_cmd_usage_help']
            except:
                sub_commands.remove(x_command)
        sub_commands = " ".join(sub_commands)
        print(sub_commands)
        return

    # Check for subcommand option.
    if sub_command and cur.startswith("-"):
        try:
            cmd_help = help_dict[sub_command]['cmd']
            cmd_help = cmd_help.split()
        except KeyError:
            cmd_help = []
        for x in cmd_help:
            if not x.startswith("-"):
                continue
            print(x)
        return

    # Check for subcommand parameters.
    if prev_word.startswith("-"):
        cmd_help = help_dict[sub_command]['cmd']
        cmd_help = cmd_help.split()
        counter = 0
        for x in cmd_help:
            counter += 1
            if x != prev_word:
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

