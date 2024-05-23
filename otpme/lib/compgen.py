# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import sys
import importlib

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import help
#from otpme.lib import config
from otpme.lib import backend
from otpme.lib.help import global_opts
from otpme.lib.help import command_map
from otpme.lib.register import register_modules
from otpme.lib.help.register import register_help
from otpme.lib.classes.command_handler import CommandHandler

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

    if '"' in cur:
        cur = cur.replace('"', '')

    tool_name = comp_words[0]
    main_command  = tool_name.split("-")[1]

    # Get previous word.
    prev_word_pos = len(comp_words) - 1
    if comp_words[-1] == cur:
        prev_word_pos -= 1
    prev_word = comp_words[prev_word_pos]

    ## Get previous previous word.
    #prev_prev_word_pos = len(comp_words) - 2
    #if comp_words[-1] == cur:
    #    prev_prev_word_pos -= 1
    #prev_prev_word = comp_words[prev_prev_word_pos]

    # Check for stdout redirection.
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
        # Parameter to the --type option may conflict with subcommands.
        if prev_subcommand_word == "--type":
            break
        if cur == word:
            break
        sub_command = word
        found_subcommand = True
        word_counter += 1

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
                                    token_types = list(command_map['token'])
                                    token_types.remove("main")
                                    token_types = " ".join(token_types)
                                    print(token_types)
                                if main_command == "policy":
                                    policy_types = list(command_map['policy'])
                                    policy_types.remove("main")
                                    policy_types = " ".join(policy_types)
                                    print(policy_types)
                                if main_command == "resolver":
                                    resolver_types = list(command_map['resolver'])
                                    resolver_types.remove("main")
                                    resolver_types = " ".join(resolver_types)
                                    print(resolver_types)
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

    register_modules()
    if object_type in config.tree_object_types:
        need_objects = True
    if object_type == "token":
        need_objects = True

    if sub_command == "add_acl":
        show_acls = False
        acl_object = None
        found_add_acl = False
        found_subcommand = False
        found_add_acl_role = False
        found_add_acl_token = False
        found_add_acl_role_cmd = False
        found_add_acl_token_cmd = False
        # Remove options.
        check_words = list(comp_words)
        for word in list(check_words):
            if not word.startswith("-"):
                continue
            check_words.remove(word)
        found_object = False
        word_counter = -1
        for word in check_words:
            word_counter += 1
            if word == sub_command:
                found_subcommand = True
            if not found_subcommand:
                continue
            if sub_command == "add_acl":
                found_add_acl = True
            if found_add_acl:
                if word == "add_acl":
                    try:
                        next_word = check_words[word_counter+1]
                    except IndexError:
                        next_word = None
                    if next_word:
                        if next_word != cur:
                            found_object = True
                if word == "token":
                    found_add_acl_token_cmd = True
                    found_add_acl_token = True
                    acl_object = check_words[word_counter-1]
                if word == "role":
                    found_add_acl_role_cmd = True
                    found_add_acl_role = True
                    acl_object = check_words[word_counter-1]
            if found_add_acl_token_cmd:
                _cur = check_words[word_counter]
                if cur != _cur:
                    _prev_word = check_words[word_counter-1]
                    if _prev_word == "token":
                        show_acls = True
            if found_add_acl_role_cmd:
                _cur = check_words[word_counter]
                if cur != _cur:
                    _prev_word = check_words[word_counter-1]
                    if _prev_word == "role":
                        show_acls = True

        if config.use_api:
            backend.init()

        if show_acls:
            all_acls = []
            if main_command == "token":
                command_args = {'token_path':acl_object}
                command_handler = CommandHandler()
                token_type = command_handler.send_command(daemon="mgmtd",
                                                    command="get_token_type",
                                                    command_args=command_args,
                                                    parse_command_syntax=False)
                token_mod = "otpme.lib.token.%s.%s" % (token_type, token_type)
                token_module = importlib.import_module(token_mod)
                token_get_acls = getattr(token_module, "get_acls")
                token_get_value_acls = getattr(token_module, "get_value_acls")
                token_get_default_acls = getattr(token_module, "get_default_acls")
                token_get_recursive_default_acls = getattr(token_module, "get_recursive_default_acls")
                token_acls = token_get_acls()
                for acl in token_acls:
                    if acl in all_acls:
                        continue
                    all_acls.append(acl)
                token_value_acls = token_get_value_acls()
                for acl in token_value_acls:
                    for x in token_value_acls[acl]:
                        acl_str = "%s:%s" % (acl, x)
                        if acl_str in all_acls:
                            continue
                        all_acls.append(acl_str)
                token_default_acls = token_get_default_acls()
                for acl in token_default_acls:
                    acl_otype = acl.split("+")[1].split(":")[0]
                    sub_types = config.get_sub_object_types(acl_otype)
                    if sub_types:
                        for sub_type in sub_types:
                            object_module_path = ("otpme.lib.%s.%s.%s"
                                                % (acl_otype, sub_type, sub_type))
                            object_module = importlib.import_module(object_module_path)
                            for a in object_module.get_acls():
                                default_acl = "+%s:%s" % (acl_otype, a)
                                if default_acl in all_acls:
                                    continue
                                all_acls.append(default_acl)
                    else:
                        object_module_path = "otpme.lib.classes.%s" % object_type
                        object_module = importlib.import_module(object_module_path)
                        for a in object_module.get_acls():
                            default_acl = "+%s:%s" % (object_type, a)
                            if default_acl in all_acls:
                                all_acls.append(default_acl)
                token_recursive_default_acls = token_get_recursive_default_acls()
                for acl in token_recursive_default_acls:
                    if acl.startswith("+"):
                        acl_otype = acl.split("+")[1].split(":")[0]
                        sub_types = config.get_sub_object_types(acl_otype)
                        if sub_types:
                            for sub_type in sub_types:
                                object_module_path = ("otpme.lib.%s.%s.%s"
                                                    % (acl_otype, sub_type, sub_type))
                                object_module = importlib.import_module(object_module_path)
                                for a in object_module.get_acls():
                                    default_acl = "++%s:%s" % (acl_otype, a)
                                    if default_acl in all_acls:
                                        continue
                                    all_acls.append(default_acl)
                        else:
                            object_module_path = "otpme.lib.classes.%s" % object_type
                            object_module = importlib.import_module(object_module_path)
                            for a in object_module.get_acls():
                                default_acl = "++%s:%s" % (object_type, a)
                                if default_acl in all_acls:
                                    continue
                                all_acls.append(default_acl)
                    else:
                        default_acl = "++%s" % acl
                        if default_acl not in all_acls:
                            all_acls.append(default_acl)

            elif main_command == "policy":
                command_args = {'policy_name':acl_object}
                command_handler = CommandHandler()
                policy_type = command_handler.send_command(daemon="mgmtd",
                                                    command="get_policy_type",
                                                    command_args=command_args,
                                                    parse_command_syntax=False)
                policy_mod = "otpme.lib.policy.%s.%s" % (policy_type, policy_type)
                policy_module = importlib.import_module(policy_mod)
                policy_get_acls = getattr(policy_module, "get_acls")
                policy_get_value_acls = getattr(policy_module, "get_value_acls")
                policy_get_default_acls = getattr(policy_module, "get_default_acls")
                policy_get_recursive_default_acls = getattr(policy_module, "get_recursive_default_acls")
                policy_acls = policy_get_acls()
                for acl in policy_acls:
                    if acl in all_acls:
                        continue
                    all_acls.append(acl)
                policy_value_acls = policy_get_value_acls()
                for acl in policy_value_acls:
                    for x in policy_value_acls[acl]:
                        acl_str = "%s:%s" % (acl, x)
                        if acl_str in all_acls:
                            continue
                        all_acls.append(acl_str)
                policy_default_acls = policy_get_default_acls()
                for acl in policy_default_acls:
                    if acl.startswith("+"):
                        acl_otype = acl.split("+")[1].split(":")[0]
                        sub_types = config.get_sub_object_types(acl_otype)
                        if sub_types:
                            for sub_type in sub_types:
                                object_module_path = ("otpme.lib.%s.%s.%s"
                                                    % (acl_otype, sub_type, sub_type))
                                object_module = importlib.import_module(object_module_path)
                                for a in object_module.get_acls():
                                    default_acl = "+%s:%s" % (acl_otype, a)
                                    if default_acl in all_acls:
                                        continue
                                    all_acls.append(default_acl)
                        else:
                            object_module_path = "otpme.lib.classes.%s" % object_type
                            object_module = importlib.import_module(object_module_path)
                            for a in object_module.get_acls():
                                default_acl = "+%s:%s" % (object_type, a)
                                if default_acl in all_acls:
                                    continue
                                all_acls.append(default_acl)
                    else:
                        default_acl = "+%s" % acl
                        if default_acl not in all_acls:
                            all_acls.append(default_acl)
                policy_recursive_default_acls = policy_get_recursive_default_acls()
                for acl in policy_recursive_default_acls:
                    if acl.startswith("+"):
                        acl_otype = acl.split("+")[1].split(":")[0]
                        sub_types = config.get_sub_object_types(acl_otype)
                        if sub_types:
                            for sub_type in sub_types:
                                object_module_path = ("otpme.lib.%s.%s.%s"
                                                    % (acl_otype, sub_type, sub_type))
                                object_module = importlib.import_module(object_module_path)
                                for a in object_module.get_acls():
                                    default_acl = "++%s:%s" % (acl_otype, a)
                                    if default_acl in all_acls:
                                        continue
                                    all_acls.append(default_acl)
                        else:
                            object_module_path = "otpme.lib.classes.%s" % object_type
                            object_module = importlib.import_module(object_module_path)
                            for a in object_module.get_acls():
                                default_acl = "++%s:%s" % (object_type, a)
                                if default_acl in all_acls:
                                    continue
                                all_acls.append(default_acl)
                    else:
                        default_acl = "++%s" % acl
                        if default_acl not in all_acls:
                            all_acls.append(default_acl)
            else:
                x_mod = "otpme.lib.classes.%s" % object_type
                x_module = importlib.import_module(x_mod)
                x_get_acls = getattr(x_module, "get_acls")
                x_get_value_acls = getattr(x_module, "get_value_acls")
                x_get_default_acls = getattr(x_module, "get_default_acls")
                x_get_recursive_default_acls = getattr(x_module, "get_recursive_default_acls")
                x_acls = x_get_acls()
                for acl in x_acls:
                    if acl in all_acls:
                        continue
                    all_acls.append(acl)
                x_value_acls = x_get_value_acls()
                for acl in x_value_acls:
                    for x in x_value_acls[acl]:
                        acl_str = "%s:%s" % (acl, x)
                        if acl_str in all_acls:
                            continue
                        all_acls.append(acl_str)
                x_default_acls = x_get_default_acls()
                for acl in x_default_acls:
                    if acl.startswith("+"):
                        acl_otype = acl.split("+")[1].split(":")[0]
                        sub_types = config.get_sub_object_types(acl_otype)
                        if sub_types:
                            for sub_type in sub_types:
                                object_module_path = ("otpme.lib.%s.%s.%s"
                                                    % (acl_otype, sub_type, sub_type))
                                object_module = importlib.import_module(object_module_path)
                                for a in object_module.get_acls():
                                    default_acl = "+%s:%s" % (acl_otype, a)
                                    if default_acl in all_acls:
                                        continue
                                    all_acls.append(default_acl)

                        object_module_path = "otpme.lib.classes.%s" % acl_otype
                        object_module = importlib.import_module(object_module_path)
                        for a in object_module.get_acls():
                            acl = a.replace("+", "")
                            default_acl = "+%s:%s" % (acl_otype, acl)
                            if default_acl in all_acls:
                                continue
                            all_acls.append(default_acl)
                    else:
                        default_acl = "+%s" % acl
                        if default_acl in all_acls:
                            continue
                        all_acls.append(default_acl)
                x_recursive_default_acls = x_get_recursive_default_acls()
                for acl in x_recursive_default_acls:
                    if acl.startswith("+"):
                        acl_otype = acl.split("+")[1].split(":")[0]
                        sub_types = config.get_sub_object_types(acl_otype)
                        if sub_types:
                            for sub_type in sub_types:
                                object_module_path = ("otpme.lib.%s.%s.%s"
                                                    % (acl_otype, sub_type, sub_type))
                                object_module = importlib.import_module(object_module_path)
                                for a in object_module.get_acls():
                                    default_acl = "++%s:%s" % (acl_otype, a)
                                    if default_acl in all_acls:
                                        continue
                                    all_acls.append(default_acl)

                        object_module_path = "otpme.lib.classes.%s" % acl_otype
                        object_module = importlib.import_module(object_module_path)
                        for a in object_module.get_acls():
                            acl = a.replace("+", "")
                            default_acl = "++%s:%s" % (acl_otype, acl)
                            if default_acl in all_acls:
                                continue
                            all_acls.append(default_acl)
                    else:
                        default_acl = "++%s" % acl
                        if default_acl in all_acls:
                            continue
                        all_acls.append(default_acl)
            all_acls = "\n".join(all_acls)
            print(all_acls)
            return

        if found_add_acl_token:
            need_objects = True
            object_type = "token"
        elif found_add_acl_role:
            need_objects = True
            object_type = "role"
        elif found_object:
            print("role")
            print("token")
            return

    if sub_command == "del_acl":
        # Remove options.
        check_words = list(comp_words)
        for word in list(check_words):
            if not word.startswith("-"):
                continue
            check_words.remove(word)
        show_acls = False
        acl_object = None
        word_counter = -1
        for word in check_words:
            word_counter += 1
            if word != "del_acl":
                continue
            try:
                acl_object = check_words[word_counter+1]
            except IndexError:
                acl_object = None
            if acl_object:
                if cur == acl_object:
                    acl_object = None
                    break
            break
        if acl_object:
            show_acls = True
        if show_acls:
            command_handler = CommandHandler()
            cmd_line = ["show_acls", acl_object]
            object_acls = command_handler.handle_command(command=object_type,
                                                    command_line=cmd_line,
                                                    client_type="RAPI")
            object_acls = "\n".join(object_acls)
            print(object_acls)
            return

    if need_objects:
        if object_type == "user":
            config.cli_object_type = "main"
        command_handler = CommandHandler()
        cmd_line = ["list"]
        if cur:
            cmd_line.append("%s*" % cur)
        objects = command_handler.handle_command(command=object_type,
                                                command_line=cmd_line)
        if main_command == "token":
            if sub_command == "add":
                for x in objects.split():
                    x_str = "%s/" % x
                    print(x_str)
            else:
                print(objects)
        else:
            print(objects)

