# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import sys
import importlib

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        msg = _("Loading module: {module}")
        msg = msg.format(module=__name__)
        print(msg)
except Exception:
    pass

from otpme.lib import help
#from otpme.lib import config
from otpme.lib import backend
from otpme.lib.help import global_opts
from otpme.lib.help import command_map
from otpme.lib.register import register_modules
from otpme.lib.help.register import register_help

register_help()

# What a recursive ACL reaches, per object type. A recursive ACL is not
# for the object it is named on but for the objects below it, so those
# are the ACLs to offer: a unit does not support "enable:object", the
# users in it do. None means everything the tree holds.
RECURSIVE_ACL_TYPES = {
                    'realm'     : None,
                    'site'      : None,
                    'unit'      : None,
                    'user'      : ["token"],
                    }

# Parameters that stand for the object the command is for. It is the
# first parameter of every command that takes one, and the regex of a
# list command matches its name, so both complete from the same list.
OBJECT_PARAMETERS = ["|object|", "|objects|", "search_regex"]

# Commands that build their completion further down on their own.
OWN_COMPLETION_COMMANDS = ["add_acl", "del_acl"]

# What a parameter of a command names. The key is the parameter as the
# command syntax writes it with what wraps it taken off (see the
# command_map comment in otpme/lib/help/__init__.py), the value the
# object type whose names complete it. The value of an option is looked
# up here as well, which is why some keys read like an option
# ("default_role") and others like a parameter ("role_name").
PARAMETER_OBJECT_TYPES = {
                    'access_group'          : "accessgroup",
                    'agent_script'          : "script",
                    'auth_script'           : "script",
                    'client'                : "client",
                    'client_name'           : "client",
                    'default_role'          : "role",
                    'default_roles'         : "role",
                    'default_token'         : "token",
                    'destination_script'    : "script",
                    'destination_token'     : "token",
                    'device_name'           : "device",
                    'group'                 : "group",
                    'group_name'            : "group",
                    'groups'                : "group",
                    'host'                  : ["host", "node"],
                    'host_name'             : "host",
                    'hosts'                 : ["host", "node"],
                    'key_script'            : "script",
                    'login_script'          : "script",
                    'mount_script'          : "script",
                    'new_group'             : "group",
                    'new_master_node'       : "node",
                    'new_token_path'        : "token",
                    'new_unit'              : "unit",
                    'node'                  : "node",
                    'node_name'             : "node",
                    'policy_name'           : "policy",
                    'pool_name'             : "pool",
                    'realm'                 : "realm",
                    'role_name'             : "role",
                    'role_path'             : "role",
                    'roles'                 : "role",
                    'script'                : "script",
                    'second_factor_token'   : "token",
                    'site'                  : "site",
                    'site_name'             : "site",
                    'token'                 : "token",
                    'token_name'            : "token",
                    'token_path'            : "token",
                    'unit'                  : "unit",
                    'unit_path'             : "unit",
                    'units'                 : "unit",
                    'user'                  : "user",
                    'user_name'             : "user",
                    'username'              : "user",
                    'vote_script'           : "script",
                    }

# Parameters that take one of a fixed set of values. A command that
# takes other ones than these says so itself, with an "ovals" of its
# own in its help (see otpme/lib/help/user.py), and that one wins.
PARAMETER_VALUES = {
                    'encrypt_algo'  : ["rsa", "x25519"],
                    'host_type'     : ["host", "node"],
                    'key_mode'      : ["client", "server"],
                    'mode'          : ["mode1", "mode2"],
                    'new_mode'      : ["mode1", "mode2"],
                    'return_type'   : ["name", "read_oid", "full_oid", "uuid"],
                    'sign_algo'     : ["rsa", "ed25519"],
                    'uv'            : ["discouraged", "preferred", "required"],
                    }

# Parameters that name something the object of the command holds, and
# the command that lists it. "otpme-user del_token" wants one of the
# tokens of that user by its bare name, and every token of the realm is
# neither the right list nor the right spelling.
PARAMETER_MEMBER_COMMANDS = {
                    'token_name'    : "list_tokens",
                    }

# Characters bash breaks a word at although they stand inside one
# parameter: a list is written "a,b,c" and an attribute "name=value",
# and each of them is one parameter of the command.
WORD_JOINERS = [",", "="]

# What the syntax wraps a parameter in. Stripped off in this order,
# and again until nothing comes off: ":[groups]:" is a list and an
# option value at once.
PARAMETER_WRAPPERS = [
                    ("<", ">"),
                    ("[", "]"),
                    (":", ":"),
                    ("+", "+"),
                    ("{", "}"),
                    ('"', '"'),
                    ]

def strip_parameter(parameter):
    """ The name of a parameter, without what the syntax wraps it in. """
    name = parameter
    # "<attribute>=[value]" is one word on the command line and names
    # the attribute; what stands behind the "=" is its value.
    if "=" in name:
        head = name.split("=")[0]
        if head.endswith(">") or head.endswith("]"):
            name = head
    while True:
        stripped = name
        for start, end in PARAMETER_WRAPPERS:
            if not stripped.startswith(start):
                continue
            if not stripped.endswith(end):
                continue
            if len(stripped) <= len(start) + len(end):
                continue
            stripped = stripped[len(start):-len(end)]
        if stripped.startswith("file:"):
            stripped = stripped[len("file:"):]
        if stripped == name:
            return name
        name = stripped

def split_command_syntax(command_syntax):
    """ The options and the parameters of a command.

    An option maps to the name of the value it takes, and to None where
    it is a flag that takes none. The parameters come in the order the
    command expects them, the object of the command first.
    """
    opts = {}
    parameters = []
    words = command_syntax.split()
    word_pos = -1
    while True:
        word_pos += 1
        if word_pos >= len(words):
            return opts, parameters
        word = words[word_pos]
        if not word.startswith("-"):
            parameters.append(strip_parameter(word))
            continue
        value = ""
        if word_pos + 1 < len(words):
            value = words[word_pos+1]
        if not value.startswith(":"):
            # An option that is not followed by a value spec at all.
            opts[word] = None
            continue
        word_pos += 1
        if "=" in value:
            # ":enabled=True:" is the value the option stands for, not
            # one to be given on the command line.
            opts[word] = None
            continue
        opts[word] = strip_parameter(value)

def option_value_parameter(opts, comp_words, comp_cword):
    """ The value of which option the word being completed is.

    None where it is not one. A list is written "a,b,c" and the comma
    is a word of its own (see COMP_WORDBREAKS in bash_completion/otpme),
    so the option can stand several words back.
    """
    word_pos = comp_cword - 1
    while word_pos >= 0:
        word = comp_words[word_pos]
        if word in opts:
            return opts[word]
        if word in WORD_JOINERS:
            word_pos -= 1
            continue
        # The word being completed can be the comma itself, so look at
        # it as well and not only at what stands before it.
        if word_pos + 1 < len(comp_words):
            if comp_words[word_pos+1] in WORD_JOINERS:
                word_pos -= 1
                continue
        return None
    return None

def command_positionals(opts, comp_words, comp_cword, sub_command_pos):
    """ The parameters of the command that already stand on the line.

    Without the options and without their values, and a list counts as
    the one parameter it is.
    """
    positionals = []
    word_pos = sub_command_pos + 1
    while word_pos < comp_cword:
        word = comp_words[word_pos]
        if word in opts:
            word_pos += 1
            if opts[word]:
                word_pos += 1
                while word_pos + 1 < comp_cword:
                    if comp_words[word_pos] not in WORD_JOINERS:
                        break
                    word_pos += 2
            continue
        if word in WORD_JOINERS:
            word_pos += 1
            continue
        # A list is written "a,b,c" and an attribute "name=value", and
        # bash hands each piece over as a word of its own. All of them
        # together are the one parameter.
        positional = ""
        while word_pos < comp_cword:
            positional += comp_words[word_pos]
            word_pos += 1
            if word_pos >= len(comp_words):
                break
            if comp_words[word_pos] not in WORD_JOINERS:
                break
            positional += comp_words[word_pos]
            word_pos += 1
        positionals.append(positional)
    return positionals

def object_type_values(object_type):
    """ The object types the tree holds. """
    from otpme.lib import config
    return list(config.tree_object_types)

def extension_values(object_type):
    """ The extensions an object of this type can be given. """
    from otpme.lib import config
    from otpme.lib.extensions import utils
    extensions = []
    for x_ext in config.get_extensions():
        try:
            ext = utils.get_extension(x_ext)
        except Exception:
            # An extension that cannot say what it is for is one we
            # cannot offer, which is no reason to offer none at all.
            continue
        if object_type not in ext.object_types:
            continue
        extensions.append(x_ext)
    return extensions

def object_class_values(object_type):
    """ The object classes the extensions of this type bring along. """
    from otpme.lib.extensions import utils
    object_classes = []
    for x_ext in extension_values(object_type):
        ext = utils.get_extension(x_ext)
        for object_class in ext.object_classes.get(object_type, []):
            if object_class in object_classes:
                continue
            object_classes.append(object_class)
    return object_classes

def attribute_values(object_type):
    """ The LDIF attributes an object of this type can carry. """
    from otpme.lib.extensions import utils
    # The attributes come out of the schema files, and nothing has read
    # them yet where we run outside a daemon.
    utils.load_schemas()
    attributes = []
    for x_ext in extension_values(object_type):
        ext = utils.get_extension(x_ext)
        for attribute in ext.get_valid_attributes(object_type):
            if attribute in attributes:
                continue
            attributes.append(attribute)
    return attributes

def table_header_values(object_type):
    """ The columns the object list of this type has. """
    from otpme.lib import cli
    try:
        return list(cli.object_register[object_type]['table_headers'])
    except KeyError:
        return []

def language_values(object_type):
    """ The languages OTPme was translated into. """
    from otpme.lib import config
    languages = ["en"]
    try:
        languages += sorted(os.listdir(config.locale_dir))
    except OSError:
        pass
    return languages

def sub_type_values(command):
    """ The types a command knows, e.g. the token types of otpme-token.

    Empty for a command that has no types of its own.
    """
    try:
        types = list(command_map[command])
    except KeyError:
        return []
    if "main" in types:
        types.remove("main")
    return types

def token_type_values(object_type):
    return sub_type_values("token")

def policy_type_values(object_type):
    return sub_type_values("policy")

def signer_type_values(object_type):
    """ The kinds of signature OTPme knows. """
    from otpme.lib.classes.signing import OTPmeSigner
    return list(OTPmeSigner.supported_signer_types)

def hardware_field_values(object_type):
    """ The hardware fields a host may be searched by, "name=" and all.

    The value behind the "=" is the one thing we cannot say. A field
    that is a number may be compared instead ("memory>8G"), which is
    typed over the "=".
    """
    from otpme.lib.inventory import HARDWARE_SEARCH_FIELDS
    from otpme.lib.inventory import HARDWARE_FIELD_ALIASES
    fields = list(HARDWARE_SEARCH_FIELDS)
    fields += [x for x in HARDWARE_FIELD_ALIASES if x not in fields]
    return [f"{x}=" for x in sorted(fields)]

def conf_job_type_values(object_type):
    """ The kinds of configuration management job there are. """
    from otpme.lib.classes.data_objects.conf_job import get_job_types
    return get_job_types()

def conf_job_actions(job_type):
    """ The actions one kind of configuration management job knows. """
    from otpme.lib.classes.data_objects.conf_job import get_job_actions
    try:
        return get_job_actions(job_type)
    except Exception:
        # A job type that is half typed or does not exist at all.
        return []

def conf_job_args(job_type, action):
    """ The arguments one action of a job takes, "name=" and all.

    The value behind the "=" is the one thing we cannot say, so the
    name is offered with the "=" already on it.
    """
    from otpme.lib.classes.data_objects.conf_job import CONF_JOB_ACTIONS
    try:
        x_action = CONF_JOB_ACTIONS[job_type][action]
    except KeyError:
        return []
    args = list(x_action.get('args', []))
    args += list(x_action.get('oargs', []))
    return [f"{x}=" for x in args]

# Parameters whose values are not a fixed list but can be worked out.
# What builds the list is given the type of the object the command is
# for, because the answer often depends on it.
PARAMETER_VALUE_SOURCES = {
                    'attribute'             : attribute_values,
                    'attributes'            : attribute_values,
                    'job_type'              : conf_job_type_values,
                    'default_token_type'    : token_type_values,
                    'extension'             : extension_values,
                    'hardware'              : hardware_field_values,
                    'language'              : language_values,
                    'object_class'          : object_class_values,
                    'object_type'           : object_type_values,
                    'object_types'          : object_type_values,
                    'output_fields'         : table_header_values,
                    'policy_types'          : policy_type_values,
                    'signer_type'           : signer_type_values,
                    'sort_by'               : table_header_values,
                    'token_type'            : token_type_values,
                    'token_types'           : token_type_values,
                    }

def config_parameters(object_type):
    """ The config parameters an object of this type takes. """
    from otpme.lib import config
    parameters = []
    for name in config.valid_config_params:
        object_types = config.valid_config_params[name]['object_types']
        if object_type not in object_types:
            continue
        parameters.append(name)
    return parameters

def config_parameter_values(parameter):
    """ The values a config parameter takes, where they are known. """
    from otpme.lib import config
    try:
        x_param = config.valid_config_params[parameter]
    except KeyError:
        return []
    if x_param['valid_values']:
        return [str(x) for x in x_param['valid_values']]
    if x_param['type'] == bool:
        return ["True", "False"]
    return []

def can_list_objects(object_type):
    """ Whether objects of this type can be listed by name.

    Not everything a command is for is an object in the tree: the
    trash holds entries and has no "list" at all.
    """
    return "list" in help.get_cmd_help(object_type, mod_name="main")

def member_list_command(help_dict, sub_command):
    """ The command that lists what the object already holds.

    "remove_role" takes a role the object has, and an object that can
    hold roles has a "list_roles" that names them. Without one we
    cannot narrow it down and every object of the type is offered.
    """
    for prefix in ["remove_", "del_"]:
        if not sub_command.startswith(prefix):
            continue
        member = sub_command[len(prefix):]
        if member.endswith("y"):
            member = f"{member[:-1]}ies"
        else:
            member = f"{member}s"
        list_command = f"list_{member}"
        if list_command in help_dict:
            return list_command
    return None

def object_type_acls(object_type, all_acls):
    """ Add the ACLs one object type supports to the ones we have. """
    module_path = f"otpme.lib.classes.{object_type}"
    try:
        object_module = importlib.import_module(module_path)
        type_acls = object_module.get_acls()
        type_value_acls = object_module.get_value_acls()
    except Exception:
        # A type that cannot say what it supports is one we cannot
        # complete, which is no reason to complete nothing at all.
        return all_acls
    for acl in type_acls:
        if acl in all_acls:
            continue
        all_acls.append(acl)
    for acl in type_value_acls:
        for x in type_value_acls[acl]:
            acl_str = f"{acl}:{x}"
            if acl_str in all_acls:
                continue
            all_acls.append(acl_str)
    return all_acls

def recursive_acl_types(object_type, comp_words):
    """ The object types a recursive ACL on this object would reach.

    Empty where the command line does not ask for one, and empty where
    this kind of object has nothing below it.
    """
    from otpme.lib import config
    if "-r" not in comp_words:
        return []
    if object_type not in RECURSIVE_ACL_TYPES:
        return []
    member_types = RECURSIVE_ACL_TYPES[object_type]
    if member_types is None:
        member_types = config.tree_object_types
    # "--objects user,group" says which of them it is meant for, and
    # the ACLs of the others are noise then.
    try:
        objects_opt = comp_words.index("--objects")
        wanted_types = comp_words[objects_opt + 1].split(",")
    except (ValueError, IndexError):
        wanted_types = []
    if wanted_types:
        member_types = [x for x in member_types if x in wanted_types]
    return member_types

def process_acls(default_acls, all_acls, recursive=False):
    from otpme.lib import config
    for acl in default_acls:
        if acl.startswith("+"):
            acl_otype = acl.split("+")[1].split(":")[0]
            # Handle subtypes.
            sub_types = config.get_sub_object_types(acl_otype)
            if sub_types:
                for sub_type in sub_types:
                    object_module_path = f"otpme.lib.{acl_otype}.{sub_type}.{sub_type}"
                    object_module = importlib.import_module(object_module_path)
                    for a in object_module.get_acls():
                        default_acl = f"+{acl_otype}:{a}"
                        if recursive:
                            default_acl = f"+{default_acl}"
                        if default_acl in all_acls:
                            continue
                        all_acls.append(default_acl)
                    x_value_acls = object_module.get_value_acls()
                    for a in x_value_acls:
                        for x_acl in x_value_acls[a]:
                            default_acl = f"+{acl_otype}:{a}:{x_acl}"
                            if recursive:
                                default_acl = f"+{default_acl}"
                            if default_acl in all_acls:
                                continue
                            all_acls.append(default_acl)
            # Handle object default ACLs.
            object_module_path = f"otpme.lib.classes.{acl_otype}"
            object_module = importlib.import_module(object_module_path)
            for a in object_module.get_acls():
                default_acl = f"+{acl_otype}:{a}"
                if recursive:
                    default_acl = f"+{default_acl}"
                if default_acl in all_acls:
                    continue
                all_acls.append(default_acl)
            x_value_acls = object_module.get_value_acls()
            for a in x_value_acls:
                for x_acl in x_value_acls[a]:
                    default_acl = f"+{acl_otype}:{a}:{x_acl}"
                    if recursive:
                        default_acl = f"+{default_acl}"
                    if default_acl in all_acls:
                        continue
                    all_acls.append(default_acl)
        else:
            default_acl = f"+{acl}"
            if recursive:
                default_acl = f"+{default_acl}"
            if default_acl in all_acls:
                continue
            all_acls.append(default_acl)
    return all_acls

def show_compgen():
    """ Print valid compgen commands """
    from otpme.lib import config
    from otpme.lib.classes.command_handler import CommandHandler
    cur = None
    counter = 0
    comp_words = None
    comp_cword = None
    for x in sys.argv:
        if x == "--cur":
            try:
                cur = sys.argv[counter+1]
            except IndexError:
                cur = ""
            sys.argv.remove(x)
        if x == "--comp-cword":
            comp_cword = int(sys.argv[counter+1])
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

    # A command that takes no subcommand at all, such as otpme-shell
    # (see "_need_command" in its help). What follows the tool name is
    # its own parameters, so there is nothing to list and the syntax of
    # the command itself is the one to read.
    no_sub_command = not help_dict.get('_need_command', True)

    # Check if command line already includes a subcommand.
    word_counter = -1
    sub_command_pos = None
    found_subcommand = False
    sub_commands = list(help_dict)
    for word in comp_words:
        word_counter += 1
        if word not in sub_commands:
            continue
        prev_subcommand_word = comp_words[word_counter-1]
        if prev_subcommand_word == "--type":
            sub_command = None
            found_subcommand = False
            continue
        if word_counter == comp_cword:
            if cur == word:
                sub_command = None
                found_subcommand = False
                break
        if len(comp_words) >= 3:
            prev_subcommand_word = comp_words[word_counter-3]
            if cur != "":
                if prev_subcommand_word == "--type":
                    sub_command = None
                    found_subcommand = False
                    break
        sub_command = word
        sub_command_pos = word_counter
        found_subcommand = True
        break

    # A command without subcommands offers its own options beside the
    # global ones. Printed here and not left to the block further down,
    # because the global options are answered first and would be the
    # whole answer: there is no subcommand word that could tell the two
    # apart.
    if no_sub_command and cur.startswith("-"):
        for x in help_dict.get('cmd', "").split():
            if not x.startswith("-"):
                continue
            print(x)

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
                                # Whatever types the command has, and
                                # nothing for one that has none.
                                x_types = sub_type_values(main_command)
                                print(" ".join(x_types))
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

    if no_sub_command:
        # Its parameters start right after the tool name.
        sub_command_pos = 0

    if sub_command is None and not no_sub_command:
        # List all subcommands
        sub_commands = list(help_dict)
        for x_command in list(sub_commands):
            try:
                help_dict[x_command]['_cmd_usage_help']
            except Exception:
                sub_commands.remove(x_command)
        sub_commands = " ".join(sub_commands)
        print(sub_commands)
        return

    # The syntax of what is being typed: of the subcommand, or of the
    # command itself where it has no subcommands.
    try:
        if no_sub_command:
            command_syntax = help_dict['cmd']
        else:
            command_syntax = help_dict[sub_command]['cmd']
    except Exception:
        command_syntax = None

    # Check for subcommand option.
    if command_syntax and cur.startswith("-"):
        for x in command_syntax.split():
            if not x.startswith("-"):
                continue
            print(x)
        return

    # What the word being completed is: the value of an option, one of
    # the parameters of the command, or the object it is for.
    parameter = None
    object_types = []
    positionals = []
    member_command = None
    if command_syntax:
        cmd_opts, cmd_parameters = split_command_syntax(command_syntax)
        positionals = command_positionals(cmd_opts, comp_words,
                                        comp_cword, sub_command_pos)
        parameter = option_value_parameter(cmd_opts, comp_words, comp_cword)
        if parameter is None:
            if len(positionals) < len(cmd_parameters):
                parameter = cmd_parameters[len(positionals)]
            if parameter in PARAMETER_MEMBER_COMMANDS:
                member_command = PARAMETER_MEMBER_COMMANDS[parameter]
            elif parameter in PARAMETER_OBJECT_TYPES and sub_command:
                member_command = member_list_command(help_dict, sub_command)
            if member_command and not positionals:
                # It lists what the object holds, and there is no
                # object on the command line yet.
                member_command = None

    register_modules()

    if command_syntax and sub_command not in OWN_COMPLETION_COMMANDS:
        on_value_side = cur == "="
        if comp_cword > 0 and comp_words[comp_cword-1] == "=":
            on_value_side = True
        if on_value_side:
            # The right hand side of "attribute=value". Nobody can say
            # what belongs there.
            return
        # What the command says itself about the values it takes.
        try:
            command_values = help_dict[sub_command]['ovals']
        except Exception:
            command_values = {}
        if parameter in command_values:
            print("\n".join(command_values[parameter]))
            return
        if parameter in PARAMETER_VALUES:
            print("\n".join(PARAMETER_VALUES[parameter]))
            return
        if parameter in PARAMETER_VALUE_SOURCES:
            get_values = PARAMETER_VALUE_SOURCES[parameter]
            print("\n".join(get_values(object_type)))
            return
        if parameter == "parameter":
            print("\n".join(config_parameters(object_type)))
            return
        if parameter == "value" and sub_command == "config":
            # The parameter it is the value of stands right before it.
            if len(positionals) > 1:
                print("\n".join(config_parameter_values(positionals[1])))
            return
        if parameter == "action" and main_command == "deploy":
            # The job type it is an action of is the parameter before
            # it, and every type knows other actions.
            if positionals:
                print("\n".join(conf_job_actions(positionals[0])))
            return
        if parameter == "job_args" and main_command == "deploy":
            # The arguments belong to one action of one job type, and
            # both of them may still be missing: they stand behind the
            # options.
            if len(positionals) > 1:
                print("\n".join(conf_job_args(positionals[0],
                                            positionals[1])))
            return
        if parameter in OBJECT_PARAMETERS:
            object_types = [object_type]
        elif parameter in PARAMETER_OBJECT_TYPES:
            object_types = PARAMETER_OBJECT_TYPES[parameter]
            if not isinstance(object_types, list):
                object_types = [object_types]
        if member_command:
            command_handler = CommandHandler()
            cmd_line = [member_command, positionals[0]]
            try:
                members = command_handler.handle_command(command=main_command,
                                                    command_line=cmd_line,
                                                    client_type="RAPI")
            except Exception:
                # The object on the command line is half typed or does
                # not exist at all, which is no reason to answer with
                # an error message where a list belongs.
                members = []
            if isinstance(members, str):
                # A list comes back as one string, and a comma is what
                # separates its entries there.
                members = members.replace(",", "\n").split("\n")
            members = [x for x in members if x]
            if members:
                print("\n".join(members))
                return
            # The object holds none of them, or the command could not
            # say. Every object of the type is better than nothing.
        object_types = [x for x in object_types if can_list_objects(x)]
        if not object_types:
            # A parameter we know of but cannot complete, e.g. a
            # comment or a new name. The objects of the command are
            # not what goes there.
            return
        need_objects = True

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
                token_mod = f"otpme.lib.token.{token_type}.{token_type}"
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
                        acl_str = f"{acl}:{x}"
                        if acl_str in all_acls:
                            continue
                        all_acls.append(acl_str)
                token_default_acls = token_get_default_acls()
                for acl in token_default_acls:
                    acl_otype = acl.split("+")[1].split(":")[0]
                    sub_types = config.get_sub_object_types(acl_otype)
                    if sub_types:
                        for sub_type in sub_types:
                            object_module_path = f"otpme.lib.{acl_otype}.{sub_type}.{sub_type}"
                            object_module = importlib.import_module(object_module_path)
                            for a in object_module.get_acls():
                                default_acl = f"+{acl_otype}:{a}"
                                if default_acl in all_acls:
                                    continue
                                all_acls.append(default_acl)
                    else:
                        object_module_path = f"otpme.lib.classes.{object_type}"
                        object_module = importlib.import_module(object_module_path)
                        for a in object_module.get_acls():
                            default_acl = f"+{object_type}:{a}"
                            if default_acl in all_acls:
                                all_acls.append(default_acl)
                token_recursive_default_acls = token_get_recursive_default_acls()
                for acl in token_recursive_default_acls:
                    if acl.startswith("+"):
                        acl_otype = acl.split("+")[1].split(":")[0]
                        sub_types = config.get_sub_object_types(acl_otype)
                        if sub_types:
                            for sub_type in sub_types:
                                object_module_path = f"otpme.lib.{acl_otype}.{sub_type}.{sub_type}"
                                object_module = importlib.import_module(object_module_path)
                                for a in object_module.get_acls():
                                    default_acl = f"++{acl_otype}:{a}"
                                    if default_acl in all_acls:
                                        continue
                                    all_acls.append(default_acl)
                        else:
                            object_module_path = f"otpme.lib.classes.{object_type}"
                            object_module = importlib.import_module(object_module_path)
                            for a in object_module.get_acls():
                                default_acl = f"++{object_type}:{a}"
                                if default_acl in all_acls:
                                    continue
                                all_acls.append(default_acl)
                    else:
                        default_acl = f"++{acl}"
                        if default_acl not in all_acls:
                            all_acls.append(default_acl)

            elif main_command == "policy":
                command_args = {'policy_name':acl_object}
                command_handler = CommandHandler()
                policy_type = command_handler.send_command(daemon="mgmtd",
                                                    command="get_policy_type",
                                                    command_args=command_args,
                                                    parse_command_syntax=False)
                policy_mod = f"otpme.lib.policy.{policy_type}.{policy_type}"
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
                        acl_str = f"{acl}:{x}"
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
                                object_module_path = f"otpme.lib.{acl_otype}.{sub_type}.{sub_type}"
                                object_module = importlib.import_module(object_module_path)
                                for a in object_module.get_acls():
                                    default_acl = f"+{acl_otype}:{a}"
                                    if default_acl in all_acls:
                                        continue
                                    all_acls.append(default_acl)
                        else:
                            object_module_path = f"otpme.lib.classes.{object_type}"
                            object_module = importlib.import_module(object_module_path)
                            for a in object_module.get_acls():
                                default_acl = f"+{object_type}:{a}"
                                if default_acl in all_acls:
                                    continue
                                all_acls.append(default_acl)
                    else:
                        default_acl = f"+{acl}"
                        if default_acl not in all_acls:
                            all_acls.append(default_acl)
                policy_recursive_default_acls = policy_get_recursive_default_acls()
                for acl in policy_recursive_default_acls:
                    if acl.startswith("+"):
                        acl_otype = acl.split("+")[1].split(":")[0]
                        sub_types = config.get_sub_object_types(acl_otype)
                        if sub_types:
                            for sub_type in sub_types:
                                object_module_path = f"otpme.lib.{acl_otype}.{sub_type}.{sub_type}"
                                object_module = importlib.import_module(object_module_path)
                                for a in object_module.get_acls():
                                    default_acl = f"++{acl_otype}:{a}"
                                    if default_acl in all_acls:
                                        continue
                                    all_acls.append(default_acl)
                        else:
                            object_module_path = f"otpme.lib.classes.{object_type}"
                            object_module = importlib.import_module(object_module_path)
                            for a in object_module.get_acls():
                                default_acl = f"++{object_type}:{a}"
                                if default_acl in all_acls:
                                    continue
                                all_acls.append(default_acl)
                    else:
                        default_acl = f"++{acl}"
                        if default_acl not in all_acls:
                            all_acls.append(default_acl)
            else:
                x_mod = f"otpme.lib.classes.{object_type}"
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
                        acl_str = f"{acl}:{x}"
                        if acl_str in all_acls:
                            continue
                        all_acls.append(acl_str)
                # Add default ACLs.
                x_default_acls = x_get_default_acls()
                all_acls = process_acls(x_default_acls, all_acls)
                # Add recursive default ACLs.
                x_recursive_default_acls = x_get_recursive_default_acls()
                all_acls = process_acls(x_recursive_default_acls, all_acls, recursive=True)

            # With "-r" the ACL is meant for the objects below this one,
            # so theirs belong in the list as well.
            for member_type in recursive_acl_types(object_type, comp_words):
                all_acls = object_type_acls(member_type, all_acls)

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
            cmd_line = ["list_acls", acl_object]
            object_acls = command_handler.handle_command(command=object_type,
                                                    command_line=cmd_line,
                                                    client_type="RAPI")
            object_acls = "\n".join(object_acls)
            print(object_acls)
            return

    if need_objects:
        if not object_types:
            # No parameter of the command said what to list, so it is
            # the object the command is for.
            object_types = [object_type]
        command_handler = CommandHandler()
        for x_type in object_types:
            if x_type != main_command or x_type == "user":
                # "--type" names a type of the command (e.g. a token
                # type), and the objects listed here are of another
                # type, which has no such thing.
                config.cli_object_type = "main"
            cmd_line = ["list"]
            if cur:
                cmd_line.append(f"{cur}*")
            objects = command_handler.handle_command(command=x_type,
                                                    command_line=cmd_line)
            if main_command == "token" and sub_command == "add":
                for x in objects.split():
                    x_str = f"{x}/"
                    print(x_str)
                continue
            print(objects)
