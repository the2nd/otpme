# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import sys
import pprint
import base64
import inspect
from functools import wraps
from binaryornot.check import is_binary

#from prettytable import ALL
from prettytable import FRAME
from prettytable import NONE
from prettytable import PrettyTable

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

from otpme.lib import help
from otpme.lib import stuff
from otpme.lib import config
#from otpme.lib.messages import message
from otpme.lib.messages import error_message
from otpme.lib.cache import object_list_cache

from otpme.lib.exceptions import *

default_callback = config.get_callback()

object_register = {}

REGISTER_BEFORE = []
REGISTER_AFTER = []

# Protocol modules to register.
modules = [
            #'otpme.lib.cli.__init__',
            'otpme.lib.cli.user',
            'otpme.lib.cli.accessgroup',
            'otpme.lib.cli.ca',
            'otpme.lib.cli.client',
            'otpme.lib.cli.dictionary',
            'otpme.lib.cli.group',
            'otpme.lib.cli.host',
            'otpme.lib.cli.node',
            'otpme.lib.cli.policy',
            'otpme.lib.cli.realm',
            'otpme.lib.cli.resolver',
            'otpme.lib.cli.role',
            'otpme.lib.cli.script',
            'otpme.lib.cli.site',
            'otpme.lib.cli.token',
            'otpme.lib.cli.unit',
            'otpme.lib.cli.user',
            'otpme.lib.classes',
        ]

def register():
    """ Register cli modules. """
    from otpme.lib.register import _register_modules
    _register_modules(modules)

def check_special_object(object_type, object_name):
    # Check if the current object is a base object.
    base_object = False
    internal_object = False
    if object_type in config.internal_objects:
        if object_name in config.internal_objects[object_type]:
            internal_object = True
    if object_type in config.base_objects:
        if object_name in config.base_objects[object_type]:
            base_object = True
    return base_object, internal_object

def check_rapi_opts():
    """ Decorator to check CLI opts passed to method. """
    def wrapper(f):
        @wraps(f)
        def wrapped(self, *f_args, **f_kwargs):
            func_name = f.__name__
            try:
                callback = f_kwargs['callback']
            except:
                callback = default_callback
            try:
                _caller = f_kwargs['_caller']
            except:
                _caller = "API"

            if _caller != "API":
                commands = self.__class__.commands
                # Find command that maps to this method.
                for x in commands:
                    for s in commands[x][config.server_protocol]:
                        method = commands[x][config.server_protocol][s]['method']
                        if method != func_name:
                            continue
                        command = x
                        break
                if _caller == "CLIENT":
                    # Get help dict of the command.
                    help_dict = help.get_cmd_help(self.type)
                    try:
                        ovals = help_dict[command]['ovals']
                    except:
                        ovals = []
                elif _caller == "RAPI":
                    try:
                        exists_ovals = commands[command]['exist']
                    except:
                        exists_ovals = []
                    try:
                        missing_ovals = commands[command]['missing']
                    except:
                        missing_ovals = []
                    ovals = set(exists_ovals + missing_ovals)
                else:
                    msg = "Unknown <_caller>: %s" % _caller
                    return callback.error(msg)
                # Get argument position.
                argspec = inspect.getfullargspec(f)
                for x_attr in ovals:
                    valid_values = ovals[x_attr]
                    x_index = argspec.args.index(x_attr)
                    # Try to get arg by index or from kwargs.
                    try:
                        x_val = f_args[x_index]
                    except:
                        x_val = f_kwargs[x_attr]
                    # Make sure a valid value is passed.
                    if x_val in valid_values:
                        continue
                    msg = "Invalid argument value: %s: %s" % (x_attr, x_val)
                    return callback.error(msg)
            # Call given class method.
            result = f(self, *f_args, **f_kwargs)
            return result
        return wrapped
    return wrapper

def register_cli(name, table_headers, row_getter, write_acls=[], read_acls=[],
    id_attr=None, search_regex_getter=None, sort_by="full_oid",
    search_attribute=None, return_attributes=None, max_len=None):
    """ Register stuff for CLI output commands. """
    global object_register
    if name in object_register:
        msg = "CLI already registered: %s" % name
        raise OTPmeException(msg)
    object_register[name] = {}
    object_register[name]['sort_by'] = sort_by
    object_register[name]['write_acls'] = write_acls
    object_register[name]['read_acls'] = read_acls
    object_register[name]['row_getter'] = row_getter
    object_register[name]['table_headers'] = table_headers
    if id_attr is not None:
        object_register[name]['id_attr'] = id_attr
    if search_regex_getter is not None:
        object_register[name]['search_regex_getter'] = search_regex_getter
    if search_attribute is not None:
        object_register[name]['search_attribute'] = search_attribute
    if return_attributes is not None:
        object_register[name]['return_attributes'] = return_attributes
    if max_len is not None:
        object_register[name]['max_len'] = max_len

def show_getter(object_type):
    """ Show function getter. """
    def show_x(*args, **kwargs):
        return show_objects(object_type, *args, **kwargs)
    return show_x

def list_getter(object_type):
    """ List function getter. """
    def list_x(*args, **kwargs):
        return list_objects(object_type, *args, **kwargs)
    return list_x

def get_unit_string(unit_uuid):
    """ Get unit string of objects unit. """
    from otpme.lib import backend
    return_attrs = ['path', 'enabled']
    result = backend.search(object_type="unit",
                        attribute="uuid",
                        value=unit_uuid,
                        return_attributes=return_attrs)
    unit_path = result[unit_uuid]['path']
    unit_enabled = result[unit_uuid]['enabled'][0]
    unit_path = "/".join(unit_path.split("/")[3:])
    unit_status_string = ""
    if not unit_enabled:
        unit_status_string = " (D)"
    unit_string = "%s%s" % (unit_path, unit_status_string)
    return unit_string

def get_policies_string(object_type, object_uuid, max_policies=None):
    """ Get policies string of objects policies. """
    from otpme.lib import backend
    if not isinstance(max_policies, int):
        msg = "Max policies must be a int."
        raise OTPmeJobException(msg)
    return_attrs = ['name', 'enabled', 'rel_path']
    policies_count, \
    policies_result = backend.search(object_type="policy",
                            attribute="uuid",
                            value="*",
                            join_object_type=object_type,
                            join_search_attr="uuid",
                            join_search_val=object_uuid,
                            join_attribute="policy",
                            order_by="rel_path",
                            return_query_count=True,
                            max_results=max_policies,
                            return_attributes=return_attrs)
    policies_strings = []
    for policy_uuid in policies_result:
        policy_name = policies_result[policy_uuid]['name']
        policy_enabled = policies_result[policy_uuid]['enabled'][0]
        policy_status_string = ""
        if not policy_enabled:
            policy_status_string = " (D)"
        policy_string = "%s%s" % (policy_name, policy_status_string)
        policies_strings.append(policy_string)
        if max_policies is None:
            continue
        processed_policies = len(policies_strings)
        if processed_policies == max_policies:
            if processed_policies < policies_count:
                x = ("(%s of %s policies total)"
                    % (processed_policies, policies_count))
                policies_strings.append(x)
                break
    policies_string = "\n".join(policies_strings)
    return policies_string

def get_auth_script_string(script_uuid):
    """ Get auth-script string of objects auth-script. """
    from otpme.lib import backend
    script_status = ""
    return_attributes = ['enabled', 'rel_path']
    result = backend.search(object_type="script",
                            attribute="uuid",
                            value=script_uuid,
                            return_attributes=return_attributes)
    if not result:
        msg = "Unknown auth script."
        raise UnknownObject(msg)
    script_rel_path = result[script_uuid]['rel_path']
    try:
        script_enabled = result[script_uuid]['enabled'][0]
    except:
        script_enabled = False
    if not script_enabled:
        script_status = " (D)"
    auth_script_string = "%s%s" % (script_rel_path, script_status)
    return auth_script_string

def get_console_echo(fd=sys.stdin.fileno()):
    """ Get console echo status. """
    import termios

    lflag = termios.tcgetattr(fd)[3]

    if str(termios.ECHO) in str(lflag):
        return True
    return False

def console_echo(enabled, fd=sys.stdin.fileno()):
    """ Configure console echo. """
    import termios

    iflag, \
    oflag, \
    cflag, \
    lflag, \
    ispeed, \
    ospeed, \
    cc = termios.tcgetattr(fd)

    if enabled:
        lflag |= termios.ECHO
    else:
        lflag  &= ~termios.ECHO

    new_attr = [iflag, oflag, cflag, lflag, ispeed, ospeed, cc]
    termios.tcsetattr(fd, termios.TCSANOW, new_attr)

def user_input(prompt, prefill=""):
    """
    Read user input from stdin.
    """
    import readline
    old_echo_status = get_console_echo()
    if not old_echo_status:
        console_echo(True)
    readline.set_startup_hook(lambda: readline.insert_text(prefill))
    try:
        return str(input(prompt))
    except:
        raise
    finally:
        if not old_echo_status:
            console_echo(old_echo_status)
        readline.set_startup_hook()

def read_pass(prompt='Password: '):
    """
    Read password from stdin.

    @oarg:prompt:str Password prompt.

    @example:
        input = read_pass(prompt="OTP: ")
    """
    import getpass
    try:
        return str(getpass.getpass(prompt))
    except:
        raise

def get_password(prompt='Password: ', min_len=8):
    """
    Ask user for password.

    Ask user for a new password and to repeat it until the first password
    input matches the second one.

    @oarg:prompt:str Password prompt.
    @oarg:min_len:int Require password with minimum length.

    @example:
        input = get_password(prompt="Passphrase: ")
    """
    password1 = True
    password2 = False
    while True:
        password1 = read_pass(prompt)
        if len(password1) < min_len:
            error_message(_("Password too short. (min. %s chars)") % min_len)
            continue
        password2 = read_pass('Confirm password: ')
        if password1 != password2:
            error_message('Passwords do not match.')
            continue
        break
    new_password = password1
    del(password1)
    del(password2)
    return new_password

def get_opts(command_syntax, command_line, command_args,
    ignore_unknown_opts=False):
    """
    Parse given command line and get opts from it.
    """
    cmd_opts = {}
    cmd_opt_opts = {}
    cmd_paras = {}
    cmd_opt_paras = {}
    cmd_key_val_paras = {}
    object_cmd = False
    object_required = False
    multiple_objects = False

    def check_string(x, start_chars, end_chars=None):
        if not x.startswith(start_chars):
            msg = "String does not start with: %s" % start_chars
            raise OTPmeException(msg)
        if end_chars and not x.endswith(end_chars):
            msg = "String does not end with: %s" % end_chars
            raise OTPmeException(msg)
        start_chars_len = len(start_chars)
        if end_chars:
            end_chars_len = len(end_chars)
            x = x[start_chars_len:-end_chars_len]
        else:
            x = x[start_chars_len:]
        return x

    def check_required_opt(x):
        result = check_string(x, "::", "::")
        return result

    def check_optional_opt(x):
        try:
            check_required_opt(x)
        except:
            pass
        result = check_string(x, ":", ":")
        return result

    def check_list_opt(x):
        result = check_string(x, "[", "]")
        return result

    def check_dict_opt(x):
        result = check_string(x, "{", "}")
        return result

    def check_multi_opt(x):
        result = check_string(x, "+", "+")
        return result

    para_count = 0
    cmd_list = command_syntax.split(" ")
    while len(cmd_list) > 0:
        cmd_part = cmd_list.pop(0)

        # Check for option.
        try:
            check_string(cmd_part, "-")
            found_option = True
        except:
            found_option = False

        if found_option:
            opt = cmd_part

            val_type = None
            multi_opt = False
            val = cmd_list.pop(0)
            required_opt = False
            optional_opt = False
            try:
                val = check_required_opt(val)
                required_opt = True
            except:
                pass
            try:
                val = check_optional_opt(val)
                optional_opt = True
            except:
                pass
            try:
                val = check_multi_opt(val)
                multi_opt = True
            except:
                pass
            try:
                val = check_list_opt(val)
                val_type = list
            except:
                pass
            try:
                val = check_dict_opt(val)
                val_type = dict
            except:
                pass

            if required_opt:
                #cmd_list.pop(0)
                cmd_opts[opt] = {
                                'type' : val_type,
                                'value': val,
                                'multi': multi_opt,
                                }

            if optional_opt:
                #cmd_list.pop(0)
                cmd_opt_opts[opt] = {
                                    'type' : val_type,
                                    'value': val,
                                    'multi': multi_opt,
                                    }
            continue

        # Check for key=value parameter.
        if "=" in cmd_part:
            key_name = cmd_part.split("=")[0]
            val_name = cmd_part.split("=")[1]
            cmd_key_val_paras[para_count] = (key_name, val_name)
            para_count += 1
            #cmd_list.pop(0)
            continue

        # Check for required parameter/object.
        para = cmd_part
        try:
            para = check_string(para, "<", ">")
            found_required_string = True
        except:
            found_required_string = False

        # Check for file.
        try:
            para = check_string(para, "file:")
            found_file_opt = True
        except:
            found_file_opt = False

        # Check for optional_opt parameter/object.
        try:
            para = check_string(para, "[", "]")
            found_optional_string = True
        except:
            found_optional_string = False

        # Check if we got an object command line.
        try:
            para = check_string(para, "|object|")
            found_object_string = True
            object_cmd = True
        except:
            # Check if we got an multi object command line.
            try:
                para = check_string(para, "|objects|")
                found_object_string = True
                multiple_objects = True
                object_cmd = True
            except:
                found_object_string = False

        if found_required_string:
            if found_object_string:
                object_required = True
            else:
                cmd_paras[para_count] = {}
                cmd_paras[para_count]['para'] = para
                cmd_paras[para_count]['file'] = found_file_opt
                para_count += 1
            #cmd_list.pop(0)
            continue

        if found_optional_string:
            if not found_object_string:
                cmd_opt_paras[para_count] = para
                para_count += 1
            #cmd_list.pop(0)
            continue

        msg = (_("Unknown parameter in command template: %s") % para)
        raise OTPmeException(msg)

    objects = []
    para_count = 0
    found_multi_opts = {}
    found_end_of_opts = False
    while len(command_line) > 0:
        opt = None
        opt_var = None
        opt_val = None
        para_var = None
        para_val = None
        key_name = None
        val_name = None
        check_for_otpme_opts = False
        # Dont check for otpme options after a "--"
        # on cli. (e.g. agent_script --gpg-smartcard)
        if command_line[0] == "--":
            found_end_of_opts = True
            command_line.pop(0)
            continue
        if command_line[0].startswith('-'):
            check_for_otpme_opts = True
        if found_end_of_opts:
            check_for_otpme_opts = False
        if check_for_otpme_opts:
            if command_line[0] in cmd_opts:
                #opt = cmd_opts[command_line[0]]
                opt = cmd_opts.pop(command_line[0])
            if command_line[0] in cmd_opt_opts:
                #opt = cmd_opt_opts[command_line[0]]
                opt = cmd_opt_opts.pop(command_line[0])
            if not opt:
                if command_line[0] in found_multi_opts:
                    opt = found_multi_opts[command_line[0]]
            if opt:
                var = opt['value']
                var_type = opt['type']
                multi_opt = opt['multi']
                if multi_opt:
                    found_multi_opts[command_line[0]] = opt
                if "=" in var:
                    opt_var = var.split("=")[0]
                    opt_val = var.split("=")[1]
                    opt_val = stuff.string_to_type(opt_val)
                    #if opt_val == "True":
                    #    opt_val = True
                    #elif opt_val == "False":
                    #    opt_val = False
                    #elif opt_val == "None":
                    #    opt_val = None
                    if multi_opt:
                        try:
                            opt_val_list = command_args[opt_var]
                        except:
                            opt_val_list = []
                        opt_val_list.append(opt_val)
                        command_args[opt_var] = opt_val_list
                    else:
                        command_args[opt_var] = opt_val
                    command_line.pop(0)
                else:
                    if len(command_line) < 2:
                        msg = (_("Option requires value: %s") % command_line[0])
                        raise OTPmeException(msg)
                    opt_var = opt['value']
                    var_type = opt['type']
                    command_line.pop(0)
                    opt_val = command_line[0]
                    if var_type == list:
                        opt_val = opt_val.split(",")
                    elif var_type == dict:
                        args_dict = {}
                        args_list = opt_val.split(",")
                        for x in args_list:
                            arg = x.split("=")[0]
                            val = x.split("=")[1]
                            args_dict[arg] = val
                        opt_val = args_dict
                    elif var_type == str:
                        opt_val = str(opt_val)
                    else:
                        opt_val = stuff.string_to_type(opt_val)

                    if multi_opt:
                        try:
                            opt_val_list = command_args[opt_var]
                        except:
                            opt_val_list = []
                        opt_val_list.append(opt_val)
                        command_args[opt_var] = opt_val_list
                    else:
                        command_args[opt_var] = opt_val
                    command_line.pop(0)
            else:
                if command_line[0] == "-h":
                    raise Exception("help")
                else:
                    if not ignore_unknown_opts:
                        raise Exception("Unknown option: %s" % command_line[0])
                    command_line.pop(0)
        else:
            # If this command needs an object and we do not have one yet
            # set it from the first parameter.
            if object_cmd and not objects and para_count == 0:
                if multiple_objects:
                    objects = command_line
                    break
                else:
                    objects = command_line[0]
                command_line.pop(0)
            else:
                para_is_file = False
                if para_count in cmd_paras:
                    para_var = cmd_paras[para_count]['para']
                    para_is_file = cmd_paras[para_count]['file']
                    cmd_paras.pop(para_count)
                elif para_count in cmd_opt_paras:
                    para_var = cmd_opt_paras[para_count]
                    cmd_opt_paras.pop(para_count)
                elif para_count in cmd_key_val_paras:
                    key_name = cmd_key_val_paras[para_count][0]
                    key_name = key_name.replace("<", "").replace(">", "")
                    val_optional = True
                    try:
                        val_name = cmd_key_val_paras[para_count][1]
                        if val_name.startswith("<"):
                            val_optional = False
                            val_name = val_name.replace("<", "").replace(">", "")
                        elif val_name.startswith("["):
                            val_name = val_name.replace("[", "").replace("]", "")
                    except:
                        pass

                if not para_var and not key_name:
                    if not ignore_unknown_opts:
                        msg = ("Unknown parameter: %s" % command_line[0])
                        raise OTPmeException(msg)
                    command_line.pop(0)
                    continue

                if para_var:
                    if para_is_file:
                        para_file = command_line[0]
                        file_is_binary = is_binary(para_file)
                        if file_is_binary:
                            fd = open(para_file, "rb")
                        else:
                            fd = open(para_file, "r")
                        try:
                            para_val = fd.read()
                        finally:
                            fd.close()
                        if file_is_binary:
                            para_val = base64.b64encode(para_val)
                            para_val = para_val.decode()
                    else:
                        para_val = command_line[0]
                    try:
                        para_var = check_list_opt(para_var)
                        var_type = list
                    except:
                        var_type = None
                    try:
                        para_var = check_dict_opt(para_var)
                        var_type = dict
                    except:
                        var_type = None
                    if var_type == list:
                        para_val = para_val.split(",")
                    elif var_type == dict:
                        args_dict = {}
                        args_list = para_val.split(",")
                        for x in args_list:
                            arg = x.split("=")[0]
                            val = x.split("=")[1]
                            val = stuff.string_to_type(val)
                            args_dict[arg] = val
                        para_val = args_dict
                    else:
                        para_val = stuff.string_to_type(para_val)
                    command_args[para_var] = para_val
                    command_line.pop(0)
                elif key_name:
                    if "=" in command_line[0]:
                        if not val_name:
                            msg = ("Unknown key/val parameter: %s"
                                        % command_line[0])
                            raise OTPmeException(msg)
                        key_val = command_line[0].split("=")[0]
                        val_val = command_line[0].split("=")[1]
                        val_val = stuff.string_to_type(val_val)
                        command_args[key_name] = key_val
                        command_args[val_name] = val_val
                    else:
                        key_val = command_line[0]
                        if not val_optional:
                            msg = ("Missing value for key: %s" % key_val)
                            raise OTPmeException(msg)
                        command_args[key_name] = key_val
                    command_line.pop(0)

                para_count += 1

    # Make sure we got all required options.
    if len(cmd_opts) > 0:
        msg = (_("Command incomplete: Missing options: %s")
                % ", ".join(cmd_opts))
        raise OTPmeException(msg)
    # Make sure we got all required parameters.
    if len(cmd_paras) > 0:
        msg = "Command incomplete."
        raise OTPmeException(msg)

    return object_cmd, object_required, objects, command_args

class ACLChecker(object):
    def __init__(self, acls=None):
        self.acls = acls
    def check_acl(self, acl):
        if not self.acls:
            return True
        if config.auth_token:
            if config.auth_token.is_admin():
                return True
        if config.use_api:
            if config.auth_token:
                return self._check_acl(acl)
            return True
        if not config.auth_token:
            return False
        return self._check_acl(acl)

    def _check_acl(self, acl):
        if acl in self.acls:
            return True
        if "all" in self.acls:
            return True
        from otpme.lib import otpme_acl
        _acl = otpme_acl.decode(acl)
        # Check for ACL and (sub)-values.
        value_check = None
        if _acl._value:
            value_check = "%s:%s" % (_acl.name, _acl._value)
        sub_value_check = None
        if _acl._sub_value:
            sub_value_check = "%s:%s:%s" % (_acl.name, _acl._value, _acl._sub_value)
        if value_check:
            if value_check in self.acls:
                return True
        if sub_value_check:
            if sub_value_check in self.acls:
                return True
        # For "view" ACLs we have to check "view_all" too.
        if _acl.id.startswith("view:"):
            if "view" in self.acls:
                return True
            if "view_all" in self.acls:
                return True
            value_check = None
            if _acl._value:
                value_check = "view_all:%s" % _acl._value
            sub_value_check = None
            if _acl._sub_value:
                sub_value_check = "view_all:%s:%s" % (_acl._value, _acl._sub_value)
            if value_check:
                if value_check in self.acls:
                    return True
            if sub_value_check:
                if sub_value_check in self.acls:
                    return True
        # For "view_all:" we have to check "view_all" too.
        if _acl.id.startswith("view_all:"):
            if "view_all" in self.acls:
                return True
        # For "view_public" we have to check "view_all" and "view" too.
        if _acl.id.startswith("view_public:"):
            # Check "view" ACLs.
            if "view" in self.acls:
                return True
            value_check = None
            if _acl._value:
                value_check = "view:%s" % _acl._value
            sub_value_check = None
            if _acl._sub_value:
                sub_value_check = "view:%s:%s" % (_acl._value, _acl._sub_value)
            if value_check:
                if value_check in self.acls:
                    return True
            if sub_value_check:
                if sub_value_check in self.acls:
                    return True
            # Check "view_all" ACLs.
            if "view_all" in self.acls:
                return True
            value_check = None
            if _acl._value:
                value_check = "view_all:%s" % _acl._value
            sub_value_check = None
            if _acl._sub_value:
                sub_value_check = "view_all:%s:%s" % (_acl._value, _acl._sub_value)
            if value_check:
                if value_check in self.acls:
                    return True
            if sub_value_check:
                if sub_value_check in self.acls:
                    return True
            # Check "view_public" ACLs.
            if "view_public" in self.acls:
                return True
            value_check = None
            if _acl._value:
                value_check = "view_public:%s" % _acl._value
            sub_value_check = None
            if _acl._sub_value:
                sub_value_check = "view_public:%s:%s" % (_acl._value, _acl._sub_value)
            if value_check:
                if value_check in self.acls:
                    return True
            if sub_value_check:
                if sub_value_check in self.acls:
                    return True
        return False

def show_objects(object_type, realm=None, site=None, search_regex=None,
    sort_by=None, reverse=False, max_len=None, id_attr=None, output_fields=[],
    border=True, header=True, csv=False, csv_sep=";", show_all=False,
    verify_acls=None, show_templates=False, callback=default_callback, **kwargs):
    """ Generate table to show <object_type> on terminal. """
    from otpme.lib import backend
    search_attribute="name"

    if realm is None:
        realm = config.realm
    if site is None:
        site = config.site

    if max_len is not None:
        try:
            max_len = int(max_len)
        except:
            msg = (_("<max_len> must be <int>."))
            raise OTPmeException(msg)

    write_acls = [
                "all",
                "edit",
                "edit:description",
                "add:policy",
                "remove:policy",
                "enable:object",
                "disable:object",
                "enable:acl_inheritance",
                "disable:acl_inheritance",
                ]

    read_acls = [
                "view_public",
                "view:status",
                "view:policy",
                "view:acl_inheritance",
                "view:description",
            ]

    # Get object related sort by.
    if sort_by is None:
        try:
            sort_by = object_register[object_type]['sort_by']
        except:
            sort_by = "full_oid"

    # Get object related max len.
    if max_len is None:
        try:
            max_len = object_register[object_type]['max_len']
        except:
            pass

    # Make sure max rows is set.
    max_rows = max_len
    if max_rows is None:
        max_rows = 1024

    # Add object related ACLs to check for.
    write_acls += list(object_register[object_type]['write_acls'])
    read_acls += list(object_register[object_type]['read_acls'])
    # Get object related table columns/headers.
    table_headers = list(object_register[object_type]['table_headers'])
    # Get function to handle object row data.
    row_getter = object_register[object_type]['row_getter']
    # Get ID attribute (e.g. rel_path for tokens).
    if id_attr is None:
        try:
            id_attr = object_register[object_type]['id_attr']
        except:
            pass
    # Object related search attribute.
    try:
        search_attribute = object_register[object_type]['search_attribute']
    except:
        pass
    # Object related return attribute.
    try:
        return_attributes = object_register[object_type]['return_attributes']
    except:
        return_attributes = []
    # Default search regex getter.
    try:
        search_regex_getter = object_register[object_type]['search_regex_getter']
    except:
        search_regex_getter = None
    # Get default search regex if none was given.
    if search_regex is None:
        if search_regex_getter:
            search_regex = search_regex_getter()
    # Check output fields format.
    try:
        if output_fields:
            output_fields = output_fields.split(",")
    except:
        return callback.error("Wrong format of output fields.")

    # Use a list copy of output fields to prevent changing of given list.
    if output_fields:
        output_fields = list(output_fields)
    else:
        output_fields = list(table_headers)

    # Handle +/- and normal fields.
    add_field_cmd = False
    additional_fields = []
    normal_field_cmd = False
    x_output_fields = list(table_headers)
    field_syntax_err = "Cannot mix normal and +/- field commands."
    for f in list(output_fields):
        if f.startswith("+") or f.startswith("-"):
            if normal_field_cmd:
                return callback.error(field_syntax_err)
            field_name = f[1:]
            if f.startswith("+"):
                # FIXME: can we use extension.get_valid_attributes(object_type) to get all valid attributes????
                x_output_fields.append(field_name)
                table_headers.append(field_name)
                additional_fields.append(field_name)
            else:
                try:
                    x_output_fields.remove(field_name)
                except:
                    msg = "Unknown field: %s" % field_name
                    return callback.error(msg)
                table_headers.remove(field_name)
            add_field_cmd = True
            continue
        if add_field_cmd:
            return callback.error(field_syntax_err)
        if f not in table_headers:
            if not f.startswith("ldif:"):
                msg = "Unknown field: %s" % f
                return callback.error(msg)
            # FIXME: can we use extension.get_valid_attributes(object_type) to get all valid attributes????
            table_headers.append(f)
            additional_fields.append(f)
        normal_field_cmd = True

    if add_field_cmd:
        output_fields = x_output_fields

    # Add additional fields.
    return_attributes += additional_fields
    if id_attr is not None:
        #return_attributes.insert(0, id_attr)
        return_attributes.append(id_attr)

    # Remove duplicates and sort return attributes.
    return_attributes = list(set(return_attributes))

    # Make sure we know how to switch row values later.
    pos = 0
    row_switches = []
    if not add_field_cmd:
        for x in list(table_headers):
            if x in output_fields:
                continue
            table_headers.remove(x)
        for x in list(output_fields):
            if x in table_headers:
                old_pos = table_headers.index(x)
                if old_pos != pos:
                    row_switches.append((old_pos, pos))
                table_headers.remove(x)
            table_headers.insert(pos, x)
            pos += 1

    # Handle sorting by non-index fields (via prettytable).
    manual_sort = None
    if sort_by not in config.index_attributes:
        manual_sort = sort_by
        max_len = None
        sort_by = "full_oid"
        if manual_sort not in output_fields:
            msg = ("Sorting attribute must be in output fields: %s"
                    % manual_sort)
            return callback.error(msg)
        msg = "Sorting by non-index attribute may be slow. Continue? [y/n]: "
        answer = callback.ask(msg)
        if answer.lower() != "y":
            return callback.abort()

    # We always query all units because they are hierarchic objects which is
    # not yet reprsented in the index DB.
    if object_type == "unit":
        max_len = None

    # By default we only show objects the user has edit permissions on.
    if search_regex is None:
        search_regex = "*"

    if show_all:
        show_only_editable_objects = False
    else:
        show_only_editable_objects = True

    # Handle end of line regex.
    if search_regex.endswith("$"):
        search_regex = search_regex[:-1]

    # Combine all ACLs to be checked.
    return_acls = None
    if verify_acls is None:
        verify_acls = write_acls + read_acls
        return_acls = list(verify_acls)

    # If we will show only objects the user has edit permissions on
    # we do not have to query for any "view-only" ACLs. This way the
    # query is faster and we can ensure that <max_len> works. If we
    # would query for all ACLs we could end up with less than <max_len>
    # results shown because the search would return <max_len> results
    # but we only show those with edit permissions.
    if show_only_editable_objects:
        verify_acls = write_acls

    # Admin user does not need ACL check.
    if config.auth_token:
        if config.auth_token.is_admin():
            verify_acls = None
            return_acls = None

    # In API mode without fake auth token we cannot verify ACLs.
    if config.use_api and not config.auth_token:
        verify_acls = None
        return_acls = None

    # Do not show template objects by default.
    search_attributes = {
                        search_attribute    : {'value':search_regex},
                        'template'          : {'value':show_templates},
                        }

    # Get objects based on search regex and ACLs assiged.
    object_count, result = backend.search(realm=realm,
                            site=site,
                            #attribute=search_attribute,
                            #value=search_regex,
                            attributes=search_attributes,
                            object_type=object_type,
                            order_by=sort_by,
                            reverse_order=reverse,
                            return_type="uuid",
                            max_results=max_len,
                            verify_acls=verify_acls,
                            return_acls=return_acls,
                            return_query_count=True,
                            return_attributes=return_attributes)

    object_acls = None
    if verify_acls:
        object_acls = result['acls']
        result = result['objects']

    object_order = list(result)
    if verify_acls and show_only_editable_objects:
        for x in dict(result):
            found_edit_acl = False
            for acl in object_acls[x]:
                #print("pppp", acl)
                if acl in write_acls:
                    found_edit_acl = True
                    break
            if not found_edit_acl:
                # Skip objects without edit permissions.
                object_order.remove(x)
                result.pop(x)

    # Make sure our realm is listed first.
    if object_type == "realm":
        realm_oid = backend.get_oid(object_type="realm", uuid=config.realm_uuid)
        if realm_oid in object_order:
            object_order.remove(realm_oid)
            object_order.insert(0, realm_oid)

    # Define output table using prettytable.
    table = PrettyTable(table_headers,
                        header_style="title",
                        vrules=NONE,
                        hrules=FRAME)
    table.align = "l"
    table.padding_width = 0
    table.right_padding_width = 1

    if object_type == "unit":
        tree_level = 0
        prev_unit_uuid = None
        prev_unit_unit_uuid = None

    list_len = 0
    rows_list = []

    def get_acl_checker(acls):
        acl_checker = ACLChecker(acls)
        return acl_checker.check_acl

    rows = []
    if object_order:
        rows = row_getter(realm, site, object_order, result,
                            object_type=object_type,
                            acls=object_acls,
                            id_attr=id_attr,
                            table=table,
                            acl_checker=get_acl_checker,
                            output_fields=output_fields,
                            **kwargs)
    for x in rows:
        x_row = x['row']
        x_name = x['name']
        x_uuid = x['uuid']
        rows_list.append(x_row)

        if object_type == "unit":
            _uuid = x['uuid']
            _unit_uuid = x['unit_uuid']
        # Count objects added.
        list_len += 1

        if object_type == "unit":
            # Set tree level based on previous unit.
            if prev_unit_uuid:
                if not _unit_uuid:
                    tree_level = 0
                elif _unit_uuid == prev_unit_uuid:
                    tree_level += 1
                elif _unit_uuid != prev_unit_unit_uuid:
                    tree_level -= 1

        # Add additional output fields.
        for attr in additional_fields:
            try:
                attr_value = result[x_uuid][attr]
            except:
                x_row.append("")
                continue
            attr_value = [str(a) for a in attr_value]
            attr_value = "\n".join(attr_value)
            x_row.append(attr_value)

        if object_type == "unit":
            if tree_level > 0:
                try:
                    name_pos = x_row.index(x_name)
                except ValueError:
                    name_pos = None
                if name_pos is not None:
                    _name = x_row.pop(name_pos)
                    new_name = " " * tree_level
                    #new_name += "└─"
                    new_name += "└"
                    new_name += _name
                    x_row.insert(name_pos, new_name)

        # Switch row values based on output fields given.
        for x in row_switches:
            old_pos = x[0]
            new_pos = x[1]
            el = x_row.pop(old_pos)
            x_row.insert(new_pos, el)

        # Finally we have to remember the current unit to handle the tree level.
        if object_type == "unit":
            prev_unit_uuid = _uuid
            prev_unit_unit_uuid = _unit_uuid

    # Handle sort by non-index attribute.
    if manual_sort:
        sort_column = 0
        for x in table_headers:
            if x == manual_sort:
                break
            sort_column += 1
        table_sort = lambda x: str(x[sort_column])
        rows_list = sorted(rows_list, key=table_sort)
        # Handle reverse sorting.
        if reverse:
            rows_list = reversed(rows_list)

    # Add base objects first.
    csv_list = []
    for row in rows_list:
        if csv:
            x_row = [str(x).replace("\n", ",") for x in row]
            x_row = csv_sep.join(x_row)
            csv_list.append(x_row)
        else:
            table.add_row(row)

    if csv:
        output = "\n".join(csv_list)
    else:
        # Get output string from table.
        output = table.get_string(start=0,
                            end=max_rows,
                            border=border,
                            header=header,
                            fields=output_fields)
        # Remove top/bottom borders.
        if border:
            output = "\n".join(output.split("\n")[1:-1])

        if object_count > max_rows:
            footer = (_("Size limit exceeded. Listed %s %ss out of %s.")
                        % (list_len, object_type, object_count))
        else:
            footer = (_("Total %s %s(s).") % (list_len, object_type))
        output = "%s\n\n%s" % (output, footer)
    return callback.ok(output)

class SessionEntry(object):
    def __init__(self, sessions, order_by):
        self.sessions = sessions
        self.order_by = order_by

    def __str__(self):
        return self.order_by

    def __repr__(self):
        # We need a string when object is used as dict key!
        return self.__str__()

    def __hash__(self):
        return hash(self.__str__())

    def __eq__(self, other):
        return self.order_by == other.order_by

    def __ne__(self, other):
        return self.order_by != other.order_by

    def __lt__(self, other):
        return self.__str__() < other.__str__()

    def __gt__(self, other):
        return self.__str__() > other.__str__()


def show_sessions(search_regex=None, sort_by="creation_time", reverse_sort=False,
    max_len=30, output_fields=[], header=True, border=True, csv=False, csv_sep=";",
    show_all=False, callback=default_callback, **kwargs):
    """
    Show sessions, all or selected by regex.

    Show sessions, their status etc. in a text table (PrettyTable)
    for output on a terminal.

    @oarg:sort_by:str
        Sort sessions by:
            - user
            - creation_time
            - expiration_time
            - unused_expiration_time
            - last_login
    @oarg:reverse_sort:bool Reverse sort order.
    @oarg:max_len:int Maximum sessions to add to output.

    @oarg:output_fields:list
        Output fields to show.
            Valid values are:
                - session id
                - user
                - token
                - type
                - accessgroup
                - host/client
                - host/client ip
                - last login
                - expire
                - unused exp.

    @oarg:callback:class JobCallback() class to interact with user.
    @raises:Exception If anything fails.

    @example:
        text_table = show_sessions(username="user1", sort_by="expire", max_len=50)
    """
    from datetime import datetime
    from otpme.lib import backend
    fields = []
    border = True

    try:
        if output_fields:
            output_fields = output_fields.split(",")
    except:
        return callback.error("Wrong format of output fields.")

    # Default sorting should be "newest on top" but sorted(reverse=True) is the
    # other way around. So we have to invert it.
    if reverse_sort:
        reverse_sort = False
    else:
        reverse_sort = True

    # Tree level must be negative for reverse sorting.
    if reverse_sort:
        tree_level_multiplier = -1
    else:
        tree_level_multiplier = 1


    write_acls = [
                "delete:session",
                ]

    read_acls = [
                "view:session",
            ]

    # Combine all ACLs to be checked.
    verify_acls = write_acls + read_acls

    show_username = False
    if show_all:
        show_username = True
        if search_regex is None:
            search_regex = "*"

    if search_regex is not None:
        show_username = True

    # Admin user does not need ACL check.
    if config.auth_token:
        if config.auth_token.is_admin():
            verify_acls = None
            if search_regex is None:
                search_regex = config.auth_user.name
        else:
            # Non-admin users must always do a users search to get ACLs checked.
            if search_regex is None:
                search_regex = config.auth_user.name

    # In API mode without fake auth token we cannot verify ACLs.
    if config.use_api and not config.auth_token:
        verify_acls = None

    # Get users based on ACLs.
    if verify_acls or search_regex:
        user_list = backend.search(realm=config.realm,
                                object_type="user",
                                attribute="name",
                                value=search_regex,
                                return_type="uuid",
                                order_by="name",
                                verify_acls=verify_acls)
        user_list = list(set(user_list))

    # Get all sessions.
    search_attrs = {}
    if search_regex:
        search_attrs['user_uuid'] = {'values':user_list}
    else:
        search_attrs['uuid'] = {'value':"*"}
        if config.auth_token:
            search_attrs['user_uuid'] = {'value':config.auth_token.owner_uuid}
    return_attributes = ['session_id', 'user_uuid']
    session_list = backend.search(object_type="session",
                                sort_by="user_uuid",
                                attributes=search_attrs,
                                return_type="uuid",
                                return_attributes=return_attributes)
    # Check if we got sessions for more than one user.
    user_uuids = []
    for x in session_list:
        user_uuid = session_list[x]['user_uuid']
        if user_uuid in user_uuids:
            continue
        user_uuids.append(user_uuid)
        if len(user_uuids) > 1:
            show_username = True
            break

    if show_username:
        table_headers = [
                        "session id",
                        "user",
                        "token",
                        "type",
                        "accessgroup",
                        "host/client",
                        "host/client ip",
                        "last login",
                        "expire",
                        "unused exp.",
                        ]
    else:
        table_headers = [
                        "session id",
                        "token",
                        "type",
                        "accessgroup",
                        "host/client",
                        "host/client ip",
                        "last login",
                        "expire",
                        "unused exp.",
                        ]

    for f in output_fields:
        if f in table_headers:
            fields.append(f)
        else:
            return callback.error(_("Unknown field: %s") % f)

    # Define output table using prettytable.
    table = PrettyTable(table_headers,
                        header_style="title",
                        vrules=NONE,
                        hrules=FRAME)
    table.align = "l"
    #table.align["column1"] = "r"
    #table.align["column2"] = "c"
    table.padding_width = 0
    table.right_padding_width = 1

    # Handle CSV output.
    if csv:
        csv_list = []

    # Dict with all session objects.
    all_sessions = {}
    # List that will hold all parent sessions.
    parent_session_list = []
    # List that will hold all child sessions.
    child_session_list = []
    # Walk through sessions to create a list with all child sessions.
    for session_uuid in session_list:
        session_id = session_list[session_uuid]['session_id'][0]
        session = backend.get_object(uuid=session_uuid)
        if session is None:
            continue
        all_sessions[session_id] = session
        # Walk through child sessions.
        for session_id in session.child_sessions:
            child_session_list.append(session_id)

    # Walk through child sessions to add child session object to all_sessions.
    for session_id in child_session_list:
        result = backend.get_sessions(session_id=session_id,
                                    return_type="instance")
        if not result:
            continue
        child_session = result[0]
        all_sessions[session_id] = child_session

    # Create list with parent sessions.
    for session_uuid in session_list:
        session_id = session_list[session_uuid]['session_id'][0]
        if session_id in parent_session_list:
            continue
        if session_id in child_session_list:
            continue
        if session_id not in all_sessions:
            continue
        parent_session_list.append(session_id)

    # Make sure we do not process more sessions than max_len.
    if len(parent_session_list) >= max_len:
        parent_session_list = parent_session_list[:max_len]

    # Dictionary to hold all session instances grouped by parent session.
    session_list = []
    session_count = 0
    session_add_count = 0

    for session_id in parent_session_list:
        # Get session from list in dictionary.
        parent_session = all_sessions[session_id]
        # List that will hold all session instances in the correct order.
        slist = [ parent_session ]
        # Dictionary used to sort child sessions.
        cdict = {}
        # Get all child session IDs.
        child_list = parent_session.get_child_sessions()
        # Walk trough all child sessions.
        for child_session_id in child_list:
            # Set tree level for normal or reverse order.
            tree_level = int(child_list[child_session_id]) \
                        * tree_level_multiplier
            # Get child session instance.
            child_session = all_sessions[child_session_id]
            # Set sort key based sort_by.
            if sort_by == "user":
                sort_key = str(child_session.username)
            elif sort_by == "creation_time":
                sort_key = str(child_session.creation_time)
            elif sort_by == "expiration_time":
                sort_key = str(child_session.expire_time())
            elif sort_by == "unused_expiration_time":
                sort_key = str(child_session.unused_expire_time())
            elif sort_by == "last_login":
                sort_key = str(child_session.last_login)
            else:
                sort_key = str(child_session.expire_time())

            cdict_key = "%s %s %s" % (tree_level, sort_key, child_session.name)
            cdict[cdict_key] = child_session

        # Put child sessions sorted into slist.
        for dict_key in sorted(cdict, reverse=reverse_sort):
            child_session = cdict[dict_key]
            slist.append(child_session)

        if sort_by == "user":
            sort_key = str(parent_session.username)
        elif sort_by == "creation_time":
            sort_key = str(parent_session.creation_time)
        elif sort_by == "expiration_time":
            sort_key = str(parent_session.expire_time())
        elif sort_by == "unused_expiration_time":
            sort_key = str(parent_session.unused_expire_time())
        elif sort_by == "last_login":
            sort_key = str(parent_session.last_login)
        else:
            sort_key = str(child_session.expire_time())

        # Make sure we do not process more sessions than max_len.
        session_count += len(slist)
        if session_count <= max_len:
            # Append session entry to session list..
            session_entry = SessionEntry(slist, sort_key)
            session_list.append(session_entry)
            session_add_count = session_count

    if session_count > max_len:
        footer = (_("Size limit exceeded. Listed %s sessions out of %s.")
                    % (session_add_count, session_count))
    else:
        footer = (_("Total %s sessions.") % session_add_count)

    # Walk through sorted list of sessions grouped by parent/child relation.
    for session_entry in sorted(session_list, reverse=reverse_sort):
        # Get list of child sessions for this sessions.
        sessions = session_entry.sessions
        # Helper variable to check if current session is the parent session.
        count = 0
        # Walk through list of child sessions.
        for s in sessions:
            x_row = []
            ## get last_used time
            #try:
            #  last_used = datetime.fromtimestamp(s.last_used)
            #except:
            #  pass
            # Get last_login time.
            try:
                last_login = datetime.fromtimestamp(float(s.last_login))
            except:
                pass
            # Get expire time.
            expire = datetime.fromtimestamp(s.expire_time())
            # Get unsued expire time.
            unused_expire = datetime.fromtimestamp(s.unused_expire_time())

            # Add tailing "*" for parent session IDs
            if count == 0:
                x_row.append("%s*" % s.session_id)
            else:
                x_row.append(s.session_id)

            if show_username:
                x_row.append(s.username)

            t = backend.get_object(object_type="token", uuid=s.auth_token)
            if t:
                x_row.append(t.name)
            else:
                x_row.append('unknown')

            x_row.append(s.session_type)

            # Indent child sessions.
            if count > 0:
                access_group_string = " %s" % s.access_group
            else:
                access_group_string = str(s.access_group)

            x_row.append(access_group_string)
            x_row.append(s.client)
            x_row.append(s.client_ip)

            if s.last_login:
                last_login_string = last_login.strftime('%H:%M:%S %d.%m.')
            else:
                last_login_string = " " * 15

            x_row.append(last_login_string)

            expire_string = expire.strftime('%H:%M:%S %d.%m.')
            x_row.append(expire_string)

            unused_expire_string = unused_expire.strftime('%H:%M:%S %d.%m.')
            x_row.append(unused_expire_string)

            count += 1

            # Add row to table.
            if csv:
                x_row = [str(x).replace("\n", ",") for x in x_row]
                x_row = csv_sep.join(x_row)
                csv_list.append(x_row)
            else:
                table.add_row(x_row)

    # Handle CSV output.
    if csv:
        output = "\n".join(csv_list)
    else:
        # Get output string from table.
        output = table.get_string(header=header, border=border, fields=fields)
        # Remove top border.
        if border:
            output = "\n".join(output.split("\n")[1:-1])
        output = "%s\n\n%s" % (output, footer)
    return callback.ok(output)

@object_list_cache.cache_function()
def list_objects(object_type, show_all=False, reverse=False,
    show_templates=False, search_regex=None, attribute=None, **kwargs):
    """ Handle object 'list' command. """
    from otpme.lib import backend
    write_acls = [
                "edit",
                "edit:description",
                "add:policy",
                "remove:policy",
                "enable:object",
                "disable:object",
                "enable:acl_inheritance",
                "disable:acl_inheritance",
                ]

    read_acls = [
                "view_public",
                "view:status",
                "view:policy",
                "view:acl_inheritance",
                "view:description",
            ]

    # Add object related ACLs to check for.
    write_acls += object_register[object_type]['write_acls']
    read_acls += object_register[object_type]['read_acls']

    if show_all:
        show_only_editable_objects = False
    else:
        show_only_editable_objects = True

    # Combine all ACLs to be checked.
    verify_acls = write_acls + read_acls

    # If we will show only objects the user has edit permissions on
    # we do not have to query for any "view-only" ACLs. This way the
    # query is faster.
    if show_only_editable_objects:
        verify_acls = write_acls

    # Admin user does not need ACL check.
    if config.auth_token:
        if config.auth_token.is_admin():
            verify_acls = None

    # In API mode without fake auth token we cannot verify ACLs.
    if config.use_api and not config.auth_token:
        verify_acls = None

    if search_regex is None:
        search_regex = "*"

    if search_regex.startswith("/"):
        sort_by = "path"
        return_type = "path"
        search_attribute="path"
    elif "/" in search_regex:
        sort_by = "rel_path"
        return_type = "rel_path"
        search_attribute="rel_path"
    else:
        if object_type in config.name_uniq_objects:
            sort_by = "name"
            return_type = "name"
            search_attribute="name"
        else:
            sort_by = "rel_path"
            return_type = "rel_path"
            search_attribute="rel_path"
        if attribute:
            return_type = attribute
            sort_by = attribute

    if object_type == "token":
        search_attribute="rel_path"

    # Do not show template objects by default.
    search_attributes = {
                        search_attribute    : {'value':search_regex},
                        'template'          : {'value':show_templates},
                        }
    # Get objects based on search regex and ACLs assiged.
    object_list = backend.search(realm=config.realm,
                            site=config.site,
                            #attribute=search_attribute,
                            #value=search_regex,
                            attributes=search_attributes,
                            object_type=object_type,
                            order_by=sort_by,
                            reverse_order=reverse,
                            return_type=return_type,
                            verify_acls=verify_acls)

    object_list = sorted([str(x) for x in object_list])
    response = "\n".join(object_list)

    return response

def list_sessions(show_all=False, **kwargs):
    """ Handle 'session list' command. """
    from otpme.lib import backend
    write_acls = [
                "edit:session",
                ]

    read_acls = [
                "view:session",
            ]

    if show_all:
        show_only_editable_objects = False
    else:
        show_only_editable_objects = True

    # Combine all ACLs to be checked.
    verify_acls = write_acls + read_acls

    # If we will show only objects the user has edit permissions on
    # we do not have to query for any "view-only" ACLs. This way the
    # query is faster.
    if show_only_editable_objects:
        verify_acls = write_acls

    # Admin user does not need ACL check.
    if config.auth_token:
        if config.auth_token.is_admin():
            verify_acls = None

    # In API mode without fake auth token we cannot verify ACLs.
    if config.use_api and not config.auth_token:
        verify_acls = None

    # Get users based on ACLs.
    user_list = backend.search(realm=config.realm,
                            site=config.site,
                            object_type="user",
                            attribute="uuid",
                            value="*",
                            return_type="uuid",
                            order_by="name",
                            verify_acls=verify_acls)

    # Get tokens based on ACLs.
    user_list += backend.search(realm=config.realm,
                            site=config.site,
                            object_type="token",
                            attribute="uuid",
                            value="*",
                            return_attributes=["owner_uuid"],
                            order_by="name",
                            verify_acls=verify_acls)
    user_list = list(set(user_list))

    # Get all sessions.
    session_ids = []
    search_attrs = {}
    search_attrs['owner_uuid'] = {'values':user_list}
    return_attributes = ['session_id', 'user_uuid']
    session_list = backend.search(object_type="session",
                                sort_by="owner_uuid",
                                attributes=search_attrs,
                                return_type="uuid",
                                return_attributes=return_attributes)
    # Check for each session if user is allowed to view/list it.
    for session_uuid in session_list:
        user_uuid = session_list[session_uuid]['user_uuid'][0]
        session_id = session_list[session_uuid]['session_id'][0]
        u = backend.get_object(object_type="user",
                                realm=config.realm,
                                uuid=user_uuid)
        if not u.verify_acl("view:session"):
            if not u.verify_acl("delete:session"):
                continue
        session_ids.append(session_id)
    response = "\n".join(session_ids)
    return response
